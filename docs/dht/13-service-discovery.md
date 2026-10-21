# Service Discovery and Marketplace

> **Status: PLANNED** · Scope: design only, no implementation · Last verified: 2026-10-20

## Overview

The DHT Service Discovery system enables trusted nodes to advertise services and discover providers across the network. Built on the go-trusted-platform's trust infrastructure, it provides a decentralized marketplace for e-commerce, hosting, storage, compute, API services, content delivery, and custom service offerings.

### Core Principles

1. **Trust-First Discovery**: Only nodes with TrustLevel=Trusted can advertise services (see [03-security-trust.md](03-security-trust.md))
2. **Cryptographic Verification**: All advertisements are signed by the provider's TPM-backed identity key
3. **Reputation Integration**: Search results incorporate provider reputation for informed decisions
4. **Escrow-Protected Payments**: Payment escrow ensures fair transactions between parties
5. **Multi-Protocol Access**: Services exposed via REST, gRPC, QUIC, MCP, and Unix Socket APIs

---

## Service Types

The marketplace supports both predefined and custom service types:

| Service Type | Code | Description |
|--------------|------|-------------|
| **E-commerce** | `ecommerce` | Online stores, product listings, order fulfillment |
| **Hosting** | `hosting` | Web hosting, application hosting, container services |
| **Storage** | `storage` | Distributed storage, backup services, archival |
| **Compute** | `compute` | CPU/GPU compute, batch processing, serverless functions |
| **API** | `api` | REST/gRPC APIs, data feeds, integration services |
| **Content** | `content` | CDN, media streaming, content delivery |
| **Custom** | `custom` | User-defined service types with custom metadata |

```go
type ServiceType string

const (
    ServiceTypeEcommerce ServiceType = "ecommerce"
    ServiceTypeHosting   ServiceType = "hosting"
    ServiceTypeStorage   ServiceType = "storage"
    ServiceTypeCompute   ServiceType = "compute"
    ServiceTypeAPI       ServiceType = "api"
    ServiceTypeContent   ServiceType = "content"
    ServiceTypeCustom    ServiceType = "custom"
)
```

---

## Service Advertisement Structure

### ServiceAdvertisement Type

```go
// ServiceAdvertisement represents a service listing in the DHT marketplace
type ServiceAdvertisement struct {
    // Identity
    ID            [32]byte    // Unique advertisement ID (SHA256 of content)
    NodeID        [32]byte    // Advertising node's TPM-backed identity
    ServiceType   ServiceType // Category of service offered

    // Description
    Name          string            // Human-readable service name (max 100 chars)
    Description   string            // Detailed description (max 2000 chars)
    Tags          []string          // Searchable tags (max 20 tags, 50 chars each)
    Metadata      map[string]string // Type-specific metadata

    // Pricing
    Pricing       PricingModel      // Flexible pricing configuration

    // Trust and Reputation
    Reputation    float64           // Provider's current reputation (0.0-1.0)
    TrustLevel    TrustLevel        // Trusted or Untrusted (must be Trusted)
    Certificate   []byte            // Provider's IDevID certificate (FROST-signed)

    // Client Requirements (CANONICAL)
    ClientRequirements *ClientRequirements // Provider-defined eligibility criteria for clients

    // Availability
    Capacity      CapacityInfo      // Current availability and limits
    SLA           SLATerms          // Service level agreement

    // Validity
    PublishedAt   int64             // Unix timestamp of publication
    ExpiresAt     int64             // Unix timestamp when listing expires
    Version       uint32            // Advertisement version (for updates)

    // Cryptographic Proof
    Signature     []byte            // Ed25519 signature over advertisement content
}

// ClientRequirements defines provider-configurable eligibility criteria for clients
// See 20-service-provider-requirements.md for complete system details
type ClientRequirements struct {
    // Trust Requirements
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
}

// EnforcementLevel defines how requirement violations are handled
type EnforcementLevel uint8

const (
    EnforcementAdvisory    EnforcementLevel = 0 // Show warnings but allow
    EnforcementStrict      EnforcementLevel = 1 // Block if not met
    EnforcementGracePeriod EnforcementLevel = 2 // Temporary access with grace
)

// Preset requirement templates for common use cases
var PresetRequirements = struct {
    OpenAccess    ClientRequirements // Accept all clients
    BasicTrust    ClientRequirements // Untrusted with min reputation
    StandardTrust ClientRequirements // Trusted nodes, moderate reputation
    HighTrust     ClientRequirements // Trusted nodes, high reputation
    MaxSecurity   ClientRequirements // Coordinator-level only
}{
    OpenAccess: ClientRequirements{
        MinTrustLevel:    TrustLevelUntrusted,
        MinReputation:    0.0,
        MaxViolations:    ^uint32(0),
        EnforcementLevel: EnforcementAdvisory,
    },
    BasicTrust: ClientRequirements{
        MinTrustLevel:    TrustLevelUntrusted,
        MinReputation:    0.50,
        MaxViolations:    10,
        MinNetworkAge:    7 * 24 * time.Hour,
        EnforcementLevel: EnforcementStrict,
    },
    StandardTrust: ClientRequirements{
        MinTrustLevel:     TrustLevelTrusted,
        RequireHardwareTPM: true,
        MinReputation:     0.70,
        MaxViolations:     5,
        MinNetworkAge:     30 * 24 * time.Hour,
        EnforcementLevel:  EnforcementStrict,
    },
    HighTrust: ClientRequirements{
        MinTrustLevel:     TrustLevelTrusted,
        RequireHardwareTPM: true,
        MinReputation:     0.80,
        MaxViolations:     2,
        MinNetworkAge:     90 * 24 * time.Hour,
        EnforcementLevel:  EnforcementStrict,
    },
    MaxSecurity: ClientRequirements{
        MinTrustLevel:     TrustLevelTrusted,
        RequireHardwareTPM: true,
        MinReputation:     0.95,
        MaxViolations:     0,
        MinNetworkAge:     180 * 24 * time.Hour,
        EnforcementLevel:  EnforcementStrict,
    },
}

// PricingModel defines flexible pricing options
type PricingModel struct {
    BasePrice     uint64      // Base price in smallest currency unit
    PricingUnit   PricingUnit // Unit of measurement
    Currency      string      // Currency identifier (default: network token)
    Tiers         []PriceTier // Volume-based pricing tiers
    Negotiable    bool        // Whether prices are negotiable
    MinContract   uint64      // Minimum contract duration (blocks)
}

type PricingUnit string

const (
    PricingUnitPerMonth    PricingUnit = "month"
    PricingUnitPerGBMonth  PricingUnit = "gb-month"
    PricingUnitPerCPUHour  PricingUnit = "cpu-hour"
    PricingUnitPerGPUHour  PricingUnit = "gpu-hour"
    PricingUnitPerGBTransfer PricingUnit = "gb-transfer"
    PricingUnitPerRequest  PricingUnit = "request"
    PricingUnitPerItem     PricingUnit = "item"
    PricingUnitCustom      PricingUnit = "custom"
)

type PriceTier struct {
    MinQuantity   uint64  // Minimum quantity for this tier
    PricePerUnit  uint64  // Price per unit at this tier
    Discount      float64 // Discount percentage (0.0-1.0)
}

type CapacityInfo struct {
    Available     uint64 // Current available capacity
    Maximum       uint64 // Maximum capacity
    Reserved      uint64 // Currently reserved
    Unit          string // Capacity unit (GB, CPU cores, etc.)
}

type SLATerms struct {
    Uptime        float64       // Guaranteed uptime (0.50-0.99999)
    ResponseTime  time.Duration // Maximum response time
    Support       string        // Support level (none, basic, premium)
    Penalties     []SLAPenalty  // Penalties for SLA violations
}

type SLAPenalty struct {
    Condition     string  // Violation condition
    Compensation  float64 // Compensation percentage
}
```

### Advertisement Validation

```go
// ValidateAdvertisement ensures an advertisement meets all requirements
func ValidateAdvertisement(ad *ServiceAdvertisement) error {
    // Trust requirement: Only Trusted nodes can advertise
    if ad.TrustLevel != TrustLevelTrusted {
        return ErrUntrustedNodeCannotAdvertise{NodeID: ad.NodeID}
    }

    // Verify IDevID certificate is valid and FROST-signed
    if err := verifyCertificate(ad.Certificate); err != nil {
        return ErrInvalidCertificate{NodeID: ad.NodeID, Reason: err.Error()}
    }

    // Verify signature matches NodeID
    if err := verifySignature(ad); err != nil {
        return ErrInvalidSignature{NodeID: ad.NodeID}
    }

    // Validate content constraints
    if len(ad.Name) > 100 {
        return ErrNameTooLong{Length: len(ad.Name)}
    }
    if len(ad.Description) > 2000 {
        return ErrDescriptionTooLong{Length: len(ad.Description)}
    }
    if len(ad.Tags) > 20 {
        return ErrTooManyTags{Count: len(ad.Tags)}
    }

    // Validate expiration
    if ad.ExpiresAt <= ad.PublishedAt {
        return ErrInvalidExpiration{}
    }

    return nil
}
```

### FINAL DESIGN: Client Eligibility Lifecycle

Service providers can define eligibility requirements that clients must maintain throughout the contract:

#### Requirement Drop During Service

```go
// EligibilityMonitor checks client eligibility continuously
type EligibilityMonitor struct {
    contract      *ServiceContract
    gracePeriod   time.Duration  // Default: 7 days
    checkInterval time.Duration  // Default: 1 hour
}

const (
    DefaultEligibilityGracePeriod = 7 * 24 * time.Hour  // 7 days
    DefaultEligibilityCheckInterval = 1 * time.Hour
)

// MonitorEligibility runs continuous eligibility checks
func (m *EligibilityMonitor) MonitorEligibility(ctx context.Context) {
    ticker := time.NewTicker(m.checkInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            m.checkClientEligibility()
        }
    }
}

// checkClientEligibility verifies client still meets requirements
func (m *EligibilityMonitor) checkClientEligibility() {
    client, err := GetNodeIdentity(m.contract.Consumer.NodeID)
    if err != nil {
        log.Error("failed to fetch client identity", "error", err)
        return
    }

    result, err := VerifyClientEligibility(client, m.contract.ClientRequirements, nil)
    if err != nil || !result.Eligible {
        // Client no longer eligible - enter grace period
        log.Warn("client lost eligibility, entering grace period",
            "clientID", client.NodeID,
            "failedChecks", result.FailedChecks)

        m.enterGracePeriod(client, result.FailedChecks)
    }
}

// enterGracePeriod gives client time to restore eligibility
func (m *EligibilityMonitor) enterGracePeriod(client *NodeIdentity, failedChecks []string) {
    // Pause contract
    m.contract.Status = ContractStatusSuspended

    // Create grace period state
    grace := &GracePeriodState{
        ClientID:      client.NodeID,
        ContractID:    m.contract.ContractID,
        EnteredAt:     time.Now(),
        ExpiresAt:     time.Now().Add(m.gracePeriod),
        GraceDuration: m.gracePeriod,
        FailedChecks:  failedChecks,
    }

    // Notify client
    NotifyClient(client.NodeID, &EligibilityNotification{
        Type:        "ELIGIBILITY_LOST",
        Message:     "Service paused: eligibility requirements no longer met",
        FailedChecks: failedChecks,
        GraceExpiry: grace.ExpiresAt,
        ActionRequired: "Restore eligibility to resume service",
    })

    // Schedule enforcement
    ScheduleEnforcementCheck(grace)
}

// OnGracePeriodExpiry handles expired grace period
func (m *EligibilityMonitor) OnGracePeriodExpiry(grace *GracePeriodState) {
    // Check if client restored eligibility
    client, err := GetNodeIdentity(grace.ClientID)
    if err != nil {
        m.terminateContract("failed to verify eligibility after grace period")
        return
    }

    result, err := VerifyClientEligibility(client, m.contract.ClientRequirements, nil)
    if err != nil || !result.Eligible {
        // Still not eligible - terminate contract
        m.terminateContract("eligibility not restored within grace period")
    } else {
        // Restored - resume contract
        m.contract.Status = ContractStatusActive
        log.Info("eligibility restored, contract resumed", "clientID", client.NodeID)
    }
}

// terminateContract ends contract due to eligibility loss
func (m *EligibilityMonitor) terminateContract(reason string) {
    m.contract.Status = ContractStatusTerminated

    // Provider notified
    NotifyProvider(m.contract.Provider.NodeID, &ContractNotification{
        Type:       "CONTRACT_TERMINATED",
        ContractID: m.contract.ContractID,
        Reason:     reason,
    })

    // Client notified
    NotifyClient(m.contract.Consumer.NodeID, &ContractNotification{
        Type:       "CONTRACT_TERMINATED",
        ContractID: m.contract.ContractID,
        Reason:     reason,
    })
}
```

#### Exemption Expiry Mid-Contract

When a client's exemption expires during service, same 7-day grace period applies:

```go
// MonitorExemptionExpiry checks exemption validity
func (m *EligibilityMonitor) MonitorExemptionExpiry() {
    if m.contract.ClientRequirements == nil ||
       m.contract.ClientRequirements.Exemptions == nil {
        return
    }

    // Find active exemption for consumer
    exemption := findValidExemption(m.contract.Consumer.NodeID,
        m.contract.ClientRequirements.Exemptions)

    if exemption == nil {
        return // No exemption
    }

    // Check if exemption about to expire
    timeUntilExpiry := time.Until(exemption.ExpiresAt)
    if timeUntilExpiry <= 0 {
        // Exemption expired - check if client meets requirements without it
        client, _ := GetNodeIdentity(m.contract.Consumer.NodeID)

        // Temporarily disable exemption for check
        originalExemptions := m.contract.ClientRequirements.Exemptions
        m.contract.ClientRequirements.Exemptions = nil

        result, err := VerifyClientEligibility(client, m.contract.ClientRequirements, nil)

        // Restore exemptions
        m.contract.ClientRequirements.Exemptions = originalExemptions

        if err != nil || !result.Eligible {
            // Client doesn't meet requirements - enter grace period
            m.enterGracePeriod(client, result.FailedChecks)
        }
    }
}
```

#### Provider Requirement Updates

Provider requirement changes only affect new contracts, not existing ones:

```go
// UpdateProviderRequirements updates requirements for future contracts
func UpdateProviderRequirements(
    serviceID [32]byte,
    newRequirements *ClientRequirements,
) error {
    // Update service advertisement
    ad, err := GetServiceAdvertisement(serviceID)
    if err != nil {
        return err
    }

    // Increment version
    ad.Version++
    ad.ClientRequirements = newRequirements

    // Store updated advertisement
    if err := StoreServiceAdvertisement(ad); err != nil {
        return err
    }

    // IMPORTANT: Existing contracts are NOT affected
    // They continue with requirements from contract creation time
    log.Info("provider requirements updated",
        "serviceID", serviceID,
        "version", ad.Version,
        "note", "existing contracts grandfathered")

    return nil
}

// GetActiveRequirements returns requirements applicable to this contract
func GetActiveRequirements(contract *ServiceContract) *ClientRequirements {
    // Contract always uses requirements from creation time
    // Provider requirement updates do NOT retroactively apply
    return contract.ClientRequirements
}
```

### FINAL DESIGN: Exemption Management

Providers can grant, revoke, and audit exemptions:

#### Exemption Revocation

```go
// RevokeExemption removes an active exemption
func RevokeExemption(
    exemptionID [32]byte,
    providerNodeID [32]byte,
    reason string,
    tpm TPMInterface,
    idevid *IDevIDKey,
) error {
    // Fetch exemption
    exemption, err := GetExemption(exemptionID)
    if err != nil {
        return err
    }

    // Verify provider owns this exemption
    if exemption.GrantedBy != providerNodeID {
        return ErrUnauthorizedRevocation{
            ExemptionID: exemptionID,
            AttemptedBy: providerNodeID,
        }
    }

    // Already revoked?
    if exemption.Revoked {
        return ErrExemptionAlreadyRevoked{ExemptionID: exemptionID}
    }

    // Create revocation signature
    now := time.Now()
    payload := computeRevocationPayload(exemptionID, reason, now)
    signature, err := tpm.Sign(context.Background(), idevid.Handle(), payload)
    if err != nil {
        return fmt.Errorf("failed to sign revocation: %w", err)
    }

    // Mark as revoked
    exemption.Revoked = true
    revokedAt := now
    exemption.RevokedAt = &revokedAt
    exemption.RevokedBy = &providerNodeID
    exemption.RevocationReason = reason

    // Add audit entry
    exemption.AuditTrail = append(exemption.AuditTrail, AuditEntry{
        Timestamp: now,
        Action:    "revoked",
        Actor:     providerNodeID,
        Details:   reason,
        Signature: signature,
    })

    // IMPORTANT: 24-hour notice period
    // Exemption remains valid for 24 hours to avoid mid-transaction disruption
    effectiveRevocationTime := now.Add(24 * time.Hour)
    exemption.ExpiresAt = effectiveRevocationTime

    // Store updated exemption
    if err := StoreExemption(exemption); err != nil {
        return err
    }

    // Notify affected client
    NotifyClient(exemption.NodeID, &ExemptionNotification{
        Type:        "EXEMPTION_REVOKED",
        ExemptionID: exemptionID,
        Reason:      reason,
        EffectiveAt: effectiveRevocationTime,
        Message:     "Your exemption will expire in 24 hours. Ensure you meet service requirements.",
    })

    log.Info("exemption revoked",
        "exemptionID", exemptionID,
        "grantedBy", providerNodeID,
        "affectedClient", exemption.NodeID,
        "effectiveAt", effectiveRevocationTime)

    return nil
}
```

#### Exemption Audit Trail

All exemption events are stored in DHT under provider's service advertisement:

```go
// ExemptionAuditLog stores all exemption events for a service
type ExemptionAuditLog struct {
    ServiceID   [32]byte
    ProviderID  [32]byte
    Entries     []ExemptionAuditEntry
}

// ExemptionAuditEntry records an exemption event
type ExemptionAuditEntry struct {
    ExemptionID   [32]byte
    ClientID      [32]byte
    Action        string    // "granted", "used", "revoked", "expired"
    Timestamp     time.Time
    Details       string
    Signature     []byte    // Provider signature
}

// DHT key for exemption audit log
func ExemptionAuditLogKey(serviceID [32]byte) string {
    return fmt.Sprintf("service:%x:exemptions:audit", serviceID)
}

// AppendExemptionAuditEntry adds an entry to the audit log
func AppendExemptionAuditEntry(serviceID [32]byte, entry ExemptionAuditEntry) error {
    // Fetch existing log
    logKey := ExemptionAuditLogKey(serviceID)
    logBytes, err := DHT.Get(context.Background(), logKey)

    var log ExemptionAuditLog
    if err == nil {
        if err := json.Unmarshal(logBytes, &log); err != nil {
            return err
        }
    } else {
        // Create new log
        log = ExemptionAuditLog{
            ServiceID:  serviceID,
            ProviderID: entry.Signature[:32], // Extract from signature
            Entries:    []ExemptionAuditEntry{},
        }
    }

    // Append entry
    log.Entries = append(log.Entries, entry)

    // Store updated log
    updatedBytes, err := json.Marshal(log)
    if err != nil {
        return err
    }

    return DHT.Store(context.Background(), logKey, updatedBytes)
}

// GetExemptionAuditLog retrieves full audit log for a service
func GetExemptionAuditLog(serviceID [32]byte) (*ExemptionAuditLog, error) {
    logKey := ExemptionAuditLogKey(serviceID)
    logBytes, err := DHT.Get(context.Background(), logKey)
    if err != nil {
        return nil, err
    }

    var log ExemptionAuditLog
    if err := json.Unmarshal(logBytes, &log); err != nil {
        return nil, err
    }

    return &log, nil
}
```

#### Maximum Concurrent Exemptions

Providers cannot grant more than 1000 concurrent exemptions:

```go
const MaxConcurrentExemptions = 1000

// GrantExemption creates a new exemption with limits enforced
func GrantExemption(
    serviceID [32]byte,
    clientID [32]byte,
    scopes []ExemptionScope,
    duration time.Duration,
    reason string,
    providerNodeID [32]byte,
    tpm TPMInterface,
    idevid *IDevIDKey,
) (*ExemptionEntry, error) {
    // Check current exemption count
    activeExemptions, err := CountActiveExemptions(serviceID)
    if err != nil {
        return nil, err
    }

    if activeExemptions >= MaxConcurrentExemptions {
        return nil, ErrTooManyExemptions{
            ServiceID:      serviceID,
            ActiveCount:    activeExemptions,
            MaxAllowed:     MaxConcurrentExemptions,
        }
    }

    // ... continue with exemption creation ...
}

// CountActiveExemptions returns number of non-expired exemptions
func CountActiveExemptions(serviceID [32]byte) (int, error) {
    ad, err := GetServiceAdvertisement(serviceID)
    if err != nil {
        return 0, err
    }

    if ad.ClientRequirements == nil || ad.ClientRequirements.Exemptions == nil {
        return 0, nil
    }

    count := 0
    now := time.Now()
    for _, ex := range ad.ClientRequirements.Exemptions.Exemptions {
        if !ex.Revoked && now.Before(ex.ExpiresAt) {
            count++
        }
    }

    return count, nil
}
```

### Client Eligibility Verification

When a client attempts to access a service, the system verifies they meet the provider's requirements:

```go
// VerifyClientEligibility checks if a client meets service requirements
func VerifyClientEligibility(client *NodeIdentity, requirements *ClientRequirements) error {
    if requirements == nil {
        return nil // No requirements = all clients accepted
    }

    // Trust level check
    if client.TrustLevel < requirements.MinTrustLevel {
        return ErrClientTrustLevelInsufficient{
            Required: requirements.MinTrustLevel,
            Actual:   client.TrustLevel,
        }
    }

    // Hardware TPM check
    if requirements.RequireHardwareTPM && !client.HasHardwareTPM {
        return ErrHardwareTPMRequired{NodeID: client.NodeID}
    }

    // Reputation check
    if client.Reputation < requirements.MinReputation {
        return ErrClientReputationInsufficient{
            Required: requirements.MinReputation,
            Actual:   client.Reputation,
        }
    }

    // Violation count check
    if client.ViolationCount > requirements.MaxViolations {
        return ErrClientViolationsExceeded{
            MaxAllowed: requirements.MaxViolations,
            Actual:     client.ViolationCount,
        }
    }

    // Network age check
    if client.NetworkAge < requirements.MinNetworkAge {
        return ErrClientTooNew{
            Required: requirements.MinNetworkAge,
            Actual:   client.NetworkAge,
        }
    }

    // Geographic check
    if len(requirements.AllowedRegions) > 0 {
        if !contains(requirements.AllowedRegions, client.Region) {
            return ErrClientRegionNotAllowed{
                Region:         client.Region,
                AllowedRegions: requirements.AllowedRegions,
            }
        }
    }
    if contains(requirements.BlockedRegions, client.Region) {
        return ErrClientRegionBlocked{Region: client.Region}
    }

    return nil
}

// EligibilityResult represents the outcome of eligibility verification
type EligibilityResult struct {
    Eligible      bool              // Whether client is eligible
    Error         error             // Error if not eligible
    Requirements  *ClientRequirements // Requirements that were checked
    Recommendations []string         // Suggestions to become eligible
}

// CheckEligibilityWithRecommendations provides detailed eligibility info
func CheckEligibilityWithRecommendations(client *NodeIdentity, requirements *ClientRequirements) *EligibilityResult {
    err := VerifyClientEligibility(client, requirements)
    result := &EligibilityResult{
        Eligible:     err == nil,
        Error:        err,
        Requirements: requirements,
    }

    if err != nil {
        // Generate helpful recommendations
        switch e := err.(type) {
        case ErrClientTrustLevelInsufficient:
            result.Recommendations = append(result.Recommendations,
                "Upgrade to hardware TPM to achieve Trusted status")
        case ErrClientReputationInsufficient:
            result.Recommendations = append(result.Recommendations,
                fmt.Sprintf("Increase reputation from %.2f to %.2f through positive network participation",
                    e.Actual, e.Required))
        case ErrClientTooNew:
            result.Recommendations = append(result.Recommendations,
                fmt.Sprintf("Wait %v more time on network",
                    e.Required-e.Actual))
        case ErrClientViolationsExceeded:
            result.Recommendations = append(result.Recommendations,
                "Reduce violation count through good behavior over time")
        }
    }

    return result
}
```

### Eligibility Error Responses

When clients don't meet requirements, they receive clear error messages:

```go
// Typed errors for client eligibility failures
type ErrClientTrustLevelInsufficient struct {
    Required TrustLevel
    Actual   TrustLevel
}

func (e ErrClientTrustLevelInsufficient) Error() string {
    return fmt.Sprintf("client trust level %d insufficient, requires %d",
        e.Actual, e.Required)
}

type ErrClientReputationInsufficient struct {
    Required float64
    Actual   float64
}

func (e ErrClientReputationInsufficient) Error() string {
    return fmt.Sprintf("client reputation %.2f insufficient, requires %.2f",
        e.Actual, e.Required)
}

type ErrClientTooNew struct {
    Required time.Duration
    Actual   time.Duration
}

func (e ErrClientTooNew) Error() string {
    return fmt.Sprintf("client network age %v insufficient, requires %v",
        e.Actual, e.Required)
}

type ErrClientViolationsExceeded struct {
    MaxAllowed uint32
    Actual     uint32
}

func (e ErrClientViolationsExceeded) Error() string {
    return fmt.Sprintf("client violation count %d exceeds maximum %d",
        e.Actual, e.MaxAllowed)
}

type ErrClientRegionNotAllowed struct {
    Region         string
    AllowedRegions []string
}

func (e ErrClientRegionNotAllowed) Error() string {
    return fmt.Sprintf("client region %s not in allowed regions %v",
        e.Region, e.AllowedRegions)
}

type ErrClientRegionBlocked struct {
    Region string
}

func (e ErrClientRegionBlocked) Error() string {
    return fmt.Sprintf("client region %s is blocked", e.Region)
}

type ErrHardwareTPMRequired struct {
    NodeID [32]byte
}

func (e ErrHardwareTPMRequired) Error() string {
    return "service requires hardware TPM attestation"
}
```

---

## Search Interface

### SearchService Interface

```go
// SearchService provides service discovery functionality
type SearchService interface {
    // Advertise publishes a service advertisement to the DHT
    Advertise(ctx context.Context, ad *ServiceAdvertisement) error

    // Search finds services matching the query criteria
    Search(ctx context.Context, query *SearchQuery) (*SearchResult, error)

    // Browse retrieves services by type with pagination
    Browse(ctx context.Context, serviceType ServiceType, opts *BrowseOptions) (*SearchResult, error)

    // GetService retrieves a specific service by ID
    GetService(ctx context.Context, serviceID [32]byte) (*ServiceAdvertisement, error)

    // RemoveAdvertisement removes a service listing
    RemoveAdvertisement(ctx context.Context, serviceID [32]byte, signature []byte) error

    // UpdateAdvertisement updates an existing listing
    UpdateAdvertisement(ctx context.Context, ad *ServiceAdvertisement) error

    // Subscribe registers for notifications about new services
    Subscribe(ctx context.Context, filter *SubscriptionFilter) (<-chan *ServiceAdvertisement, error)

    // GetProviderServices returns all services from a specific provider
    GetProviderServices(ctx context.Context, nodeID [32]byte) ([]*ServiceAdvertisement, error)
}
```

### Implementation

```go
type dhtSearchService struct {
    dht         DHT
    reputation  ReputationService
    trustVerify TrustVerifier
    index       *ServiceIndex
}

func NewSearchService(dht DHT, rep ReputationService, trust TrustVerifier) SearchService {
    return &dhtSearchService{
        dht:         dht,
        reputation:  rep,
        trustVerify: trust,
        index:       NewServiceIndex(),
    }
}

func (s *dhtSearchService) Advertise(ctx context.Context, ad *ServiceAdvertisement) error {
    // Validate advertisement
    if err := ValidateAdvertisement(ad); err != nil {
        return err
    }

    // Verify caller owns the NodeID
    if err := s.trustVerify.VerifyOwnership(ctx, ad.NodeID, ad.Certificate); err != nil {
        return ErrOwnershipVerificationFailed{NodeID: ad.NodeID}
    }

    // Update reputation from current state
    rep, err := s.reputation.GetReputation(ctx, ad.NodeID)
    if err != nil {
        return err
    }
    ad.Reputation = rep

    // Compute advertisement ID
    ad.ID = computeAdvertisementID(ad)

    // Store in DHT with multiple keys for different access patterns
    if err := s.storeAdvertisement(ctx, ad); err != nil {
        return err
    }

    // Update local index
    s.index.Add(ad)

    return nil
}

func (s *dhtSearchService) storeAdvertisement(ctx context.Context, ad *ServiceAdvertisement) error {
    adBytes, err := encodeAdvertisement(ad)
    if err != nil {
        return err
    }

    // Store under service ID
    serviceKey := fmt.Sprintf("service:%x", ad.ID)
    if err := s.dht.Store(ctx, serviceKey, adBytes); err != nil {
        return err
    }

    // Store type index entry
    typeKey := fmt.Sprintf("services:type:%s:%x", ad.ServiceType, ad.ID)
    if err := s.dht.Store(ctx, typeKey, adBytes); err != nil {
        return err
    }

    // Store tag index entries
    for _, tag := range ad.Tags {
        tagKey := fmt.Sprintf("services:tag:%s:%x", normalizeTag(tag), ad.ID)
        if err := s.dht.Store(ctx, tagKey, adBytes); err != nil {
            return err
        }
    }

    // Store node index entry
    nodeKey := fmt.Sprintf("services:node:%x:%x", ad.NodeID, ad.ID)
    if err := s.dht.Store(ctx, nodeKey, adBytes); err != nil {
        return err
    }

    return nil
}
```

---

## Search Query

### SearchQuery Structure

```go
// SearchQuery defines search criteria for service discovery
type SearchQuery struct {
    // Text search
    Keywords      []string      // Full-text search terms

    // Filters
    ServiceTypes  []ServiceType // Filter by service types (empty = all)
    Tags          []string      // Filter by tags (AND logic)
    MinReputation float64       // Minimum reputation threshold (0.0-1.0)
    TrustedOnly   bool          // Only show TrustLevel=Trusted (default: true)

    // Price filters
    PriceRange    *PriceRange   // Filter by price range

    // Geographic filters
    Regions       []string      // Filter by geographic regions

    // Availability filters
    MinCapacity   uint64        // Minimum available capacity

    // Sorting and pagination
    SortBy        SortCriteria  // Sort order
    SortOrder     SortOrder     // Ascending or descending
    Limit         uint32        // Maximum results (default: 50, max: 1000)
    Offset        uint32        // Pagination offset
}

type PriceRange struct {
    Min      uint64 // Minimum price (0 = no minimum)
    Max      uint64 // Maximum price (0 = no maximum)
    Unit     PricingUnit
    Currency string
}

type SortCriteria string

const (
    SortByRelevance   SortCriteria = "relevance"   // Text match score
    SortByReputation  SortCriteria = "reputation"  // Provider reputation
    SortByPrice       SortCriteria = "price"       // Price (low to high)
    SortByNewest      SortCriteria = "newest"      // Publication date
    SortByPopularity  SortCriteria = "popularity"  // Order count
    SortByRandom      SortCriteria = "random"      // Random order
)

type SortOrder string

const (
    SortOrderAsc  SortOrder = "asc"
    SortOrderDesc SortOrder = "desc"
)
```

### SearchResult Structure

```go
type SearchResult struct {
    Services    []*ServiceAdvertisement // Matching services
    TotalCount  uint64                   // Total matches (for pagination)
    HasMore     bool                     // More results available
    NextOffset  uint32                   // Offset for next page
    SearchTime  time.Duration            // Query execution time
}
```

### Search Implementation

```go
func (s *dhtSearchService) Search(ctx context.Context, query *SearchQuery) (*SearchResult, error) {
    start := time.Now()

    // Set defaults
    if query.Limit == 0 || query.Limit > 1000 {
        query.Limit = 50
    }
    if query.TrustedOnly {
        query.MinReputation = max(query.MinReputation, 0.0)
    }

    // Build candidate set from indexes
    candidates := s.buildCandidateSet(ctx, query)

    // Apply filters
    filtered := s.applyFilters(candidates, query)

    // Score and rank results
    scored := s.scoreResults(filtered, query)

    // Sort results
    sorted := s.sortResults(scored, query.SortBy, query.SortOrder)

    // Apply pagination
    totalCount := uint64(len(sorted))
    start := int(query.Offset)
    end := min(start+int(query.Limit), len(sorted))

    if start >= len(sorted) {
        return &SearchResult{
            Services:   []*ServiceAdvertisement{},
            TotalCount: totalCount,
            HasMore:    false,
            SearchTime: time.Since(start),
        }, nil
    }

    paginated := sorted[start:end]

    return &SearchResult{
        Services:    paginated,
        TotalCount:  totalCount,
        HasMore:     end < len(sorted),
        NextOffset:  uint32(end),
        SearchTime:  time.Since(start),
    }, nil
}

func (s *dhtSearchService) applyFilters(ads []*ServiceAdvertisement, query *SearchQuery) []*ServiceAdvertisement {
    var filtered []*ServiceAdvertisement

    for _, ad := range ads {
        // Trust filter (always enforced for trusted-only)
        if query.TrustedOnly && ad.TrustLevel != TrustLevelTrusted {
            continue
        }

        // Reputation filter
        if ad.Reputation < query.MinReputation {
            continue
        }

        // Service type filter
        if len(query.ServiceTypes) > 0 && !contains(query.ServiceTypes, ad.ServiceType) {
            continue
        }

        // Tag filter (AND logic)
        if len(query.Tags) > 0 && !hasAllTags(ad.Tags, query.Tags) {
            continue
        }

        // Price filter
        if query.PriceRange != nil && !matchesPriceRange(ad.Pricing, query.PriceRange) {
            continue
        }

        // Capacity filter
        if query.MinCapacity > 0 && ad.Capacity.Available < query.MinCapacity {
            continue
        }

        // Expiration filter (skip expired)
        if ad.ExpiresAt < time.Now().Unix() {
            continue
        }

        filtered = append(filtered, ad)
    }

    return filtered
}
```

---

## DHT Key Patterns

Service advertisements are stored under multiple DHT keys for efficient retrieval:

| Purpose | Key Pattern | Description |
|---------|-------------|-------------|
| Service by ID | `service:{id}` | Direct access to service by ID |
| Services by type | `services:type:{type}` | All services of a given type |
| Services by tag | `services:tag:{tag}` | All services with a specific tag |
| Services by node | `services:node:{node-id}` | All services from a specific provider |
| Price index | `services:price:{type}:{bucket}` | Price-bucketed index for range queries |
| Reputation index | `services:rep:{type}:{bucket}` | Reputation-bucketed index |

### Key Format Examples

```go
// Service key format
func ServiceKey(serviceID [32]byte) string {
    return fmt.Sprintf("service:%x", serviceID)
}

// Type index key format
func TypeIndexKey(serviceType ServiceType, serviceID [32]byte) string {
    return fmt.Sprintf("services:type:%s:%x", serviceType, serviceID)
}

// Tag index key format
func TagIndexKey(tag string, serviceID [32]byte) string {
    normalized := strings.ToLower(strings.TrimSpace(tag))
    return fmt.Sprintf("services:tag:%s:%x", normalized, serviceID)
}

// Node services key format
func NodeServicesKey(nodeID [32]byte, serviceID [32]byte) string {
    return fmt.Sprintf("services:node:%x:%x", nodeID, serviceID)
}

// Price bucket key format (buckets: 0-99, 100-999, 1000-9999, etc.)
func PriceBucketKey(serviceType ServiceType, price uint64) string {
    bucket := computePriceBucket(price)
    return fmt.Sprintf("services:price:%s:%d", serviceType, bucket)
}

// Reputation bucket key format (buckets: 0.0-0.1, 0.1-0.2, ..., 0.9-1.0)
func ReputationBucketKey(serviceType ServiceType, reputation float64) string {
    bucket := int(reputation * 10)
    return fmt.Sprintf("services:rep:%s:%d", serviceType, bucket)
}
```

### Index Maintenance

```go
// IndexMaintainer handles periodic cleanup and optimization
type IndexMaintainer struct {
    dht      DHT
    interval time.Duration
}

func (m *IndexMaintainer) Run(ctx context.Context) {
    ticker := time.NewTicker(m.interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            m.cleanExpiredListings(ctx)
            m.rebuildIndexes(ctx)
        }
    }
}

func (m *IndexMaintainer) cleanExpiredListings(ctx context.Context) {
    // Query all service keys
    // Remove expired advertisements
    // Update indexes accordingly
}
```

---

## E-commerce Integration

The marketplace supports full e-commerce functionality for trusted providers.

### Store and Product Types

```go
// Store represents an e-commerce storefront
type Store struct {
    StoreID       [32]byte          // Unique store identifier
    OwnerNodeID   [32]byte          // Store owner's node ID
    Name          string            // Store name
    Description   string            // Store description
    Logo          string            // Logo URL (from DHT content)
    Categories    []string          // Product categories
    Policies      StorePolicies     // Return/shipping policies
    Rating        float64           // Average customer rating
    OrderCount    uint64            // Total completed orders
    CreatedAt     int64             // Store creation timestamp
    Certificate   []byte            // Owner's IDevID certificate
    Signature     []byte            // Store data signature
}

type StorePolicies struct {
    ReturnWindow  time.Duration     // Return window (e.g., 30 days)
    ShippingZones []ShippingZone    // Available shipping regions
    PaymentTerms  []PaymentMethod   // Accepted payment methods
}

type ShippingZone struct {
    Regions       []string          // Geographic regions
    BaseRate      uint64            // Base shipping rate
    EstimatedDays int               // Estimated delivery days
}

// Product represents an item for sale
type Product struct {
    ProductID     [32]byte          // Unique product identifier
    StoreID       [32]byte          // Parent store
    Name          string            // Product name
    Description   string            // Product description
    Images        []string          // Image URLs (from DHT content)
    Category      string            // Product category
    Price         uint64            // Price in smallest currency unit
    Inventory     uint64            // Available quantity
    Variants      []ProductVariant  // Size, color, etc.
    Tags          []string          // Searchable tags
    Rating        float64           // Average product rating
    ReviewCount   uint64            // Number of reviews
    CreatedAt     int64             // Product creation timestamp
    UpdatedAt     int64             // Last update timestamp
    Signature     []byte            // Product data signature
}

type ProductVariant struct {
    VariantID     [32]byte
    Name          string            // Variant name (e.g., "Large", "Blue")
    PriceModifier int64             // Price adjustment (+/-)
    Inventory     uint64            // Variant-specific inventory
    SKU           string            // Stock keeping unit
}
```

### Order Management

```go
// Order represents a purchase transaction
type Order struct {
    OrderID       [32]byte          // Unique order identifier
    StoreID       [32]byte          // Store fulfilling order
    BuyerNodeID   [32]byte          // Buyer's node ID
    Items         []OrderItem       // Products and quantities
    Subtotal      uint64            // Items total
    ShippingCost  uint64            // Shipping cost
    Total         uint64            // Grand total
    ShippingAddr  ShippingAddress   // Delivery address (encrypted)
    Status        OrderStatus       // Current order status
    EscrowID      [32]byte          // Payment escrow reference
    CreatedAt     int64             // Order creation timestamp
    UpdatedAt     int64             // Last status update
    Signatures    OrderSignatures   // Buyer and seller signatures
}

type OrderItem struct {
    ProductID     [32]byte
    VariantID     [32]byte          // Optional variant
    Quantity      uint32
    UnitPrice     uint64
    LineTotal     uint64
}

type OrderStatus string

const (
    OrderStatusPending    OrderStatus = "pending"     // Awaiting payment
    OrderStatusPaid       OrderStatus = "paid"        // Payment in escrow
    OrderStatusProcessing OrderStatus = "processing"  // Seller preparing
    OrderStatusShipped    OrderStatus = "shipped"     // In transit
    OrderStatusDelivered  OrderStatus = "delivered"   // Delivered
    OrderStatusCompleted  OrderStatus = "completed"   // Escrow released
    OrderStatusDisputed   OrderStatus = "disputed"    // Under dispute
    OrderStatusRefunded   OrderStatus = "refunded"    // Payment returned
    OrderStatusCancelled  OrderStatus = "cancelled"   // Order cancelled
)

type OrderSignatures struct {
    BuyerSig      []byte            // Buyer's order confirmation
    SellerSig     []byte            // Seller's acceptance
    DeliverySig   []byte            // Delivery confirmation
}
```

### Checkout Flow

```
                          E-COMMERCE CHECKOUT FLOW

Buyer                     DHT Network                    Seller
-----                     -----------                    ------

  |                            |                            |
  | 1. Browse Products         |                            |
  |--------------------------->|                            |
  |                            |                            |
  | 2. Add to Cart             |                            |
  |                            |                            |
  | 3. Create Order            |                            |
  |--------------------------->|                            |
  |                            | 4. Order Created           |
  |                            |--------------------------->|
  |                            |                            |
  | 5. Create Escrow           |                            |
  |--------------------------->|                            |
  |    (Payment locked)        |                            |
  |                            |                            |
  |                            | 6. Payment Confirmed       |
  |                            |--------------------------->|
  |                            |                            |
  |                            | 7. Process & Ship          |
  |                            |<---------------------------|
  |                            |    (Status: shipped)       |
  |                            |                            |
  | 8. Receive & Confirm       |                            |
  |--------------------------->|                            |
  |    (Sign delivery)         |                            |
  |                            |                            |
  |                            | 9. Release Escrow          |
  |                            |--------------------------->|
  |                            |    (Payment to seller)     |
  |                            |                            |
  | 10. Leave Review           |                            |
  |--------------------------->|                            |
  |                            |                            |
```

### E-commerce Service Interface

```go
// EcommerceService provides marketplace functionality
type EcommerceService interface {
    // Store management
    CreateStore(ctx context.Context, store *Store) error
    UpdateStore(ctx context.Context, store *Store) error
    GetStore(ctx context.Context, storeID [32]byte) (*Store, error)

    // Product management
    CreateProduct(ctx context.Context, product *Product) error
    UpdateProduct(ctx context.Context, product *Product) error
    DeleteProduct(ctx context.Context, productID [32]byte, sig []byte) error
    GetProduct(ctx context.Context, productID [32]byte) (*Product, error)
    ListProducts(ctx context.Context, storeID [32]byte, opts *ListOptions) ([]*Product, error)
    SearchProducts(ctx context.Context, query *ProductQuery) ([]*Product, error)

    // Order management
    CreateOrder(ctx context.Context, order *Order) (*Order, error)
    GetOrder(ctx context.Context, orderID [32]byte) (*Order, error)
    UpdateOrderStatus(ctx context.Context, orderID [32]byte, status OrderStatus, sig []byte) error
    ConfirmDelivery(ctx context.Context, orderID [32]byte, buyerSig []byte) error
    ListBuyerOrders(ctx context.Context, buyerID [32]byte) ([]*Order, error)
    ListSellerOrders(ctx context.Context, sellerID [32]byte) ([]*Order, error)

    // Reviews
    CreateReview(ctx context.Context, review *Review) error
    GetProductReviews(ctx context.Context, productID [32]byte) ([]*Review, error)
    GetStoreReviews(ctx context.Context, storeID [32]byte) ([]*Review, error)
}
```

---

## Payment Escrow

Secure payment handling protects both buyers and sellers through the escrow system.

### Escrow Types

```go
// Escrow holds funds during a transaction
type Escrow struct {
    EscrowID      [32]byte          // Unique escrow identifier
    OrderID       [32]byte          // Associated order
    Amount        uint64            // Escrowed amount
    Currency      string            // Currency identifier
    Buyer         [32]byte          // Buyer's node ID
    Seller        [32]byte          // Seller's node ID
    Status        EscrowStatus      // Current escrow status
    CreatedAt     int64             // Escrow creation timestamp
    ExpiresAt     int64             // Auto-release deadline
    ReleaseConditions []ReleaseCondition // Conditions for release
    Signatures    EscrowSignatures  // Multi-party signatures

    // Dispute Protection (CANONICAL)
    DisputeWindow     time.Duration  // Mandatory dispute period (48h default)
    DisputeDeadline   time.Time      // Set when seller marks delivered
    DisputeOpen       bool           // True if buyer opened dispute
    ArbiterCommittee  []NodeID       // 5 arbiters selected via VRF
    DeliveryProof     []byte         // Proof of delivery (hash, tracking, etc.)
}

type EscrowStatus string

const (
    EscrowStatusFunding       EscrowStatus = "funding"        // Awaiting payment
    EscrowStatusFunded        EscrowStatus = "funded"         // Payment received
    EscrowStatusDelivered     EscrowStatus = "delivered"      // Seller claims delivered (NEW)
    EscrowStatusDisputeWindow EscrowStatus = "dispute_window" // 48h dispute period (NEW)
    EscrowStatusReleased      EscrowStatus = "released"       // Funds released to seller
    EscrowStatusRefunded      EscrowStatus = "refunded"       // Funds returned to buyer
    EscrowStatusDisputed      EscrowStatus = "disputed"       // Under dispute resolution
    EscrowStatusExpired       EscrowStatus = "expired"        // Auto-released after deadline
)

type ReleaseCondition struct {
    Type          ConditionType     // Delivery confirmation, time-based, etc.
    Params        map[string]string // Condition-specific parameters
    Satisfied     bool              // Whether condition is met
    SatisfiedAt   int64             // When condition was satisfied
}

type ConditionType string

const (
    ConditionDeliveryConfirmed ConditionType = "delivery_confirmed"
    ConditionTimeElapsed       ConditionType = "time_elapsed"
    ConditionArbiterApproval   ConditionType = "arbiter_approval"
    ConditionMultiSig          ConditionType = "multi_sig"
)

type EscrowSignatures struct {
    BuyerFundingSig  []byte // Buyer's funding authorization
    SellerAcceptSig  []byte // Seller's acceptance
    ReleaseSignature []byte // Release authorization
    RefundSignature  []byte // Refund authorization
    ArbiterSig       []byte // Arbiter decision (if disputed)
}
```

### Escrow Service Interface

```go
// EscrowService manages payment escrows
type EscrowService interface {
    // Create a new escrow for an order
    CreateEscrow(ctx context.Context, escrow *Escrow) (*Escrow, error)

    // Fund an escrow (buyer deposits payment)
    FundEscrow(ctx context.Context, escrowID [32]byte, txProof []byte) error

    // Release escrow to seller (after conditions met)
    ReleaseEscrow(ctx context.Context, escrowID [32]byte, signatures [][]byte) error

    // Refund escrow to buyer
    RefundEscrow(ctx context.Context, escrowID [32]byte, signatures [][]byte) error

    // Initiate dispute
    DisputeEscrow(ctx context.Context, escrowID [32]byte, reason string, evidence []byte) error

    // Arbiter resolves dispute
    ResolveDispute(ctx context.Context, escrowID [32]byte, decision DisputeDecision, sig []byte) error

    // Get escrow status
    GetEscrow(ctx context.Context, escrowID [32]byte) (*Escrow, error)

    // List active escrows for a node
    ListEscrows(ctx context.Context, nodeID [32]byte, status EscrowStatus) ([]*Escrow, error)
}

type DisputeDecision struct {
    EscrowID       [32]byte
    Decision       string   // "release", "refund", "split"
    SplitRatio     float64  // If split: percentage to seller
    Reason         string
    ArbiterID      [32]byte
    Timestamp      int64
    Signature      []byte
}

### Mandatory Dispute Window (CANONICAL)

To prevent escrow fraud where sellers falsely claim delivery, all escrows have a mandatory 48-hour dispute window before funds auto-release to seller.

#### Dispute Window Constants

```go
const (
    // DefaultDisputeWindow is the mandatory period before auto-release
    DefaultDisputeWindow = 48 * time.Hour  // CANONICAL: 48 hours

    // MinDisputeWindow prevents unreasonably short dispute periods
    MinDisputeWindow = 24 * time.Hour

    // MaxDisputeWindow prevents indefinite holds
    MaxDisputeWindow = 7 * 24 * time.Hour  // 7 days

    // ArbiterCommitteeSize is the number of arbiters per dispute
    // SECURITY (E1): Increased from 5 to 7 to prevent collusion
    ArbiterCommitteeSize = 7

    // ArbiterQuorum is the votes needed for decision
    // SECURITY (E1): Increased from 3-of-5 to 5-of-7 (71% threshold)
    ArbiterQuorum = 5  // 5-of-7

    // FINAL DESIGN: Late dispute window for buyer offline during dispute window
    LateDisputeWindow = 7 * 24 * time.Hour  // 7 days after auto-release
    LateDisputePenalty = 0.10                // 10% fee for late disputes
)
```

#### FINAL DESIGN: Escrow Edge Cases

##### Delivery Proof Validation

DeliveryProof must include cryptographic evidence to prevent fraud:

```go
// DeliveryProof contains evidence of successful delivery
type DeliveryProof struct {
    // Content hash
    DeliveredContentHash [32]byte  // SHA256 of delivered content

    // Dual signatures
    SellerSignature      []byte    // Seller's signature over content hash
    BuyerSignature       []byte    // Buyer's signature (if confirmed)

    // Metadata
    DeliveryTimestamp    time.Time
    DeliveryMethod       string    // "digital", "physical_tracking", "service_completion"

    // Method-specific proof
    TrackingNumber       string    // For physical goods
    ServiceCompletionLog []byte    // For services
    DigitalReceipt       []byte    // For digital goods
}

// ValidateDeliveryProof ensures delivery proof meets requirements
func ValidateDeliveryProof(proof *DeliveryProof, escrow *Escrow) error {
    // Must have content hash
    if proof.DeliveredContentHash == [32]byte{} {
        return ErrMissingContentHash
    }

    // Must have seller signature
    if len(proof.SellerSignature) == 0 {
        return ErrMissingSellerSignature
    }

    // Verify seller signature
    if err := verifyTPMSignature(escrow.Seller, proof.DeliveredContentHash[:], proof.SellerSignature); err != nil {
        return ErrInvalidSellerSignature{Cause: err}
    }

    // If buyer signed, verify buyer signature
    if len(proof.BuyerSignature) > 0 {
        if err := verifyTPMSignature(escrow.Buyer, proof.DeliveredContentHash[:], proof.BuyerSignature); err != nil {
            return ErrInvalidBuyerSignature{Cause: err}
        }
    }

    return nil
}
```

##### Buyer Offline During Dispute Window

If buyer is offline during the 48-hour dispute window, they can file a late dispute:

```go
// LateDispute allows buyer to dispute after auto-release
type LateDispute struct {
    EscrowID         [32]byte
    BuyerNodeID      [32]byte
    Reason           string
    Evidence         []byte
    FiledAt          time.Time
    AutoReleasedAt   time.Time  // When escrow auto-released
    PenaltyAccepted  bool       // Buyer accepts 10% penalty
}

// FileLateDispute allows dispute within 7 days of auto-release
func FileLateDispute(escrow *Escrow, reason string, evidence []byte) (*LateDispute, error) {
    now := time.Now()

    // Must be within 7 days of auto-release
    if now.After(escrow.DisputeDeadline.Add(LateDisputeWindow)) {
        return nil, ErrLateDisputeExpired{
            AutoReleasedAt: escrow.DisputeDeadline,
            FiledAt:        now,
        }
    }

    // Buyer must accept 10% penalty
    dispute := &LateDispute{
        EscrowID:        escrow.EscrowID,
        BuyerNodeID:     escrow.Buyer,
        Reason:          reason,
        Evidence:        evidence,
        FiledAt:         now,
        AutoReleasedAt:  escrow.DisputeDeadline,
        PenaltyAccepted: true,
    }

    // If buyer wins, refund is reduced by 10%
    // If seller wins, seller keeps funds and buyer pays penalty

    return dispute, nil
}
```

##### Low Arbiter Pool Handling

When the arbiter pool is small, reduce quorum requirements:

```go
// SelectArbiterCommitteeAdaptive adjusts committee size based on pool
func SelectArbiterCommitteeAdaptive(escrowID [32]byte) (*ArbiterCommittee, error) {
    // Get eligible arbiters
    candidates := GetEligibleArbiters(DefaultArbiterEligibility)
    poolSize := len(candidates)

    var committeeSize, quorum int

    switch {
    case poolSize >= 7:
        // Standard: 7 arbiters, 5-of-7 quorum
        committeeSize = 7
        quorum = 5
    case poolSize >= 5:
        // Reduced: 5 arbiters, 3-of-5 quorum
        committeeSize = 5
        quorum = 3
        log.Warn("reduced arbiter committee due to small pool", "poolSize", poolSize)
    case poolSize >= 3:
        // Minimum: 3 arbiters, 2-of-3 quorum
        committeeSize = 3
        quorum = 2
        log.Warn("minimum arbiter committee due to small pool", "poolSize", poolSize)
    default:
        // Escalate to coordinators if < 3 arbiters
        return nil, ErrInsufficientArbiters{
            Required:  3,
            Available: poolSize,
            Action:    "escalating to coordinator arbitration",
        }
    }

    // Select arbiters
    selected, err := SelectWithDiversity(GenerateArbiterSeed(escrowID, time.Now().Unix()), candidates, committeeSize)
    if err != nil {
        return nil, err
    }

    return &ArbiterCommittee{
        Arbiters:      selected,
        QuorumSize:    quorum,
        CommitteeSize: committeeSize,
    }, nil
}
```

##### High-Value Dispute Handling

For escrows above 10,000 coins, always require 7 arbiters:

```go
const HighValueThreshold = 10000 // coins

// DetermineArbiterRequirements returns committee size based on escrow value
func DetermineArbiterRequirements(escrow *Escrow) (committeeSize, quorum int) {
    if escrow.Amount >= HighValueThreshold {
        // High-value: Always 7 arbiters, 5-of-7 quorum, regardless of pool size
        return 7, 5
    }

    // Standard: Adaptive based on pool size
    return 0, 0 // Use SelectArbiterCommitteeAdaptive
}
```

#### Escrow State Machine

```go
// EscrowStateMachine enforces mandatory dispute window
type EscrowStateMachine struct {
    escrow *Escrow
}

// MarkDelivered transitions escrow to dispute window state
func (sm *EscrowStateMachine) MarkDelivered(deliveryProof []byte) error {
    if sm.escrow.Status != EscrowStatusFunded {
        return &ErrInvalidStateTransition{
            Current:  sm.escrow.Status,
            Expected: EscrowStatusFunded,
        }
    }

    // Require delivery proof
    if len(deliveryProof) == 0 {
        return ErrDeliveryProofRequired
    }

    // Transition to dispute window state (NOT released!)
    sm.escrow.Status = EscrowStatusDisputeWindow
    sm.escrow.DeliveryProof = deliveryProof
    sm.escrow.DisputeDeadline = time.Now().Add(sm.escrow.DisputeWindow)

    // Select arbiter committee via VRF (in case dispute arises)
    committee, err := SelectArbiterCommittee(sm.escrow.EscrowID)
    if err != nil {
        return err
    }
    sm.escrow.ArbiterCommittee = committee

    return nil
}

// Tick processes time-based transitions
func (sm *EscrowStateMachine) Tick() {
    if sm.escrow.Status == EscrowStatusDisputeWindow {
        if time.Now().After(sm.escrow.DisputeDeadline) {
            if !sm.escrow.DisputeOpen {
                // No dispute opened - auto-release to seller
                sm.escrow.Status = EscrowStatusReleased
            }
            // If dispute is open, remains in disputed state for resolution
        }
    }
}

// OpenDispute allows buyer to dispute before deadline
func (sm *EscrowStateMachine) OpenDispute(reason string, evidence []byte) error {
    if sm.escrow.Status != EscrowStatusDisputeWindow {
        return &ErrInvalidStateTransition{
            Current:  sm.escrow.Status,
            Expected: EscrowStatusDisputeWindow,
        }
    }

    if time.Now().After(sm.escrow.DisputeDeadline) {
        return ErrDisputeWindowExpired
    }

    sm.escrow.DisputeOpen = true
    sm.escrow.Status = EscrowStatusDisputed
    return nil
}
```

#### State Transition Diagram

```
                    ESCROW STATE MACHINE (WITH DISPUTE WINDOW)

                           +-----------+
                           |  FUNDING  |
                           +-----+-----+
                                 |
                                 | buyer funds escrow
                                 v
                           +-----+-----+
                           |  FUNDED   |
                           +-----+-----+
                                 |
                                 | seller marks delivered
                                 | (requires delivery proof)
                                 v
                    +------------+------------+
                    |     DISPUTE WINDOW      |
                    |   (48 hours mandatory)  |
                    +------------+------------+
                           /          \
          buyer disputes  /            \ 48h elapsed
          within window  /              \ (no dispute)
                        v                v
               +--------+----+    +------+------+
               |  DISPUTED   |    |  RELEASED   |
               +--------+----+    +-------------+
                        |               ^
                        | arbiter       |
                        | resolves      |
                        v               |
               +--------+----+          |
               |  DECISION   +----------+
               |             |          |
               +------+------+          |
                      |                 |
                      v                 |
               +------+------+          |
               |  REFUNDED   |          |
               +-------------+          |
                                       (auto-release to seller)
```

### VRF-Based Arbiter Selection (CANONICAL)

Arbiters are selected via VRF to ensure fair, unpredictable, and verifiable dispute resolution.

#### Arbiter Eligibility

```go
// ArbiterEligibility defines who can serve as arbiter
type ArbiterEligibility struct {
    MinReputation    float64       // 0.80+ (high trust required)
    MinUptime        float64       // 99% (reliable availability)
    MaxActiveDisputes int          // Max concurrent disputes (10)
    MinAge           time.Duration // 90 days on network
    NotInvolved      bool          // Cannot be buyer, seller, or related party
}

var DefaultArbiterEligibility = ArbiterEligibility{
    MinReputation:    0.80,
    MinUptime:        0.99,
    MaxActiveDisputes: 10,
    MinAge:           90 * 24 * time.Hour,
    NotInvolved:      true,
}

// IsEligibleArbiter checks if node can serve as arbiter
func IsEligibleArbiter(node *Node, escrow *Escrow) bool {
    // Reputation check
    if node.Reputation < DefaultArbiterEligibility.MinReputation {
        return false
    }

    // Uptime check
    if node.Uptime30Day < DefaultArbiterEligibility.MinUptime {
        return false
    }

    // Active dispute limit
    if node.ActiveDisputeCount >= DefaultArbiterEligibility.MaxActiveDisputes {
        return false
    }

    // Age check
    if time.Since(node.JoinedAt) < DefaultArbiterEligibility.MinAge {
        return false
    }

    // Conflict of interest check
    if node.ID == escrow.Buyer || node.ID == escrow.Seller {
        return false
    }

    return true
}
```

#### FINAL DESIGN: Arbiter Replacement Protocol

When arbiters refuse, go offline, or have their stake slashed, they must be replaced:

```go
const (
    ArbiterAcceptanceWindow = 24 * time.Hour  // Window to accept arbiter role
    ArbiterResponseTimeout  = 4 * time.Hour   // Timeout for offline arbiter
)

// ArbiterStatus tracks arbiter participation
type ArbiterStatus uint8

const (
    ArbiterStatusPending   ArbiterStatus = 0  // Waiting for acceptance
    ArbiterStatusAccepted  ArbiterStatus = 1  // Accepted role
    ArbiterStatusRefused   ArbiterStatus = 2  // Refused within 24h
    ArbiterStatusOffline   ArbiterStatus = 3  // No response within 4h
    ArbiterStatusDisqualified ArbiterStatus = 4  // Stake slashed mid-dispute
)

// ArbiterAssignment tracks assigned arbiter with status
type ArbiterAssignment struct {
    NodeID       [32]byte
    AssignedAt   time.Time
    Status       ArbiterStatus
    AcceptedAt   *time.Time
    RefusedAt    *time.Time
    LastSeen     time.Time
}

// ArbiterCommittee manages arbiter selection and replacement
type ArbiterCommittee struct {
    EscrowID       [32]byte
    Seed           []byte              // VRF seed
    Assignments    []ArbiterAssignment // All assignments (current + replaced)
    ActiveArbiters []NodeID            // Currently active arbiters
    Votes          map[NodeID]*ArbiterVote
    QuorumSize     int
    CommitteeSize  int
}

// SelectArbiterWithReplacement handles initial selection + replacements
func SelectArbiterWithReplacement(committee *ArbiterCommittee) error {
    seed := committee.Seed
    candidates := GetEligibleArbiters(DefaultArbiterEligibility)

    // Track which arbiters to skip (refused or disqualified)
    skipSet := make(map[[32]byte]bool)
    for _, assignment := range committee.Assignments {
        if assignment.Status == ArbiterStatusRefused ||
           assignment.Status == ArbiterStatusDisqualified {
            skipSet[assignment.NodeID] = true
        }
    }

    // Continue VRF selection from same seed, skipping refused/disqualified
    selected, err := SelectWithDiversityAndSkip(seed, candidates, committee.CommitteeSize, skipSet)
    if err != nil {
        return err
    }

    // Assign new arbiters
    for _, nodeID := range selected {
        if !isAlreadyAssigned(committee, nodeID) {
            committee.Assignments = append(committee.Assignments, ArbiterAssignment{
                NodeID:     nodeID,
                AssignedAt: time.Now(),
                Status:     ArbiterStatusPending,
                LastSeen:   time.Now(),
            })
        }
    }

    committee.ActiveArbiters = getActiveArbiters(committee)
    return nil
}

// MonitorArbiterResponses checks for timeouts and triggers replacement
func MonitorArbiterResponses(committee *ArbiterCommittee) {
    now := time.Now()

    for i := range committee.Assignments {
        assignment := &committee.Assignments[i]

        switch assignment.Status {
        case ArbiterStatusPending:
            // Check acceptance timeout (24 hours)
            if now.After(assignment.AssignedAt.Add(ArbiterAcceptanceWindow)) {
                assignment.Status = ArbiterStatusRefused
                log.Warn("arbiter refused by timeout", "nodeID", assignment.NodeID)

                // Trigger replacement
                if err := SelectArbiterWithReplacement(committee); err != nil {
                    log.Error("failed to replace arbiter", "error", err)
                }
            }

        case ArbiterStatusAccepted:
            // Check offline timeout (4 hours)
            if now.After(assignment.LastSeen.Add(ArbiterResponseTimeout)) {
                assignment.Status = ArbiterStatusOffline
                log.Warn("arbiter offline", "nodeID", assignment.NodeID)

                // Trigger replacement
                if err := SelectArbiterWithReplacement(committee); err != nil {
                    log.Error("failed to replace arbiter", "error", err)
                }
            }
        }
    }
}

// ReplaceArbiterMidDispute handles arbiter replacement during active dispute
func ReplaceArbiterMidDispute(committee *ArbiterCommittee, nodeID [32]byte, reason string) error {
    // Find arbiter in committee
    for i := range committee.Assignments {
        if committee.Assignments[i].NodeID == nodeID {
            assignment := &committee.Assignments[i]

            // Mark as disqualified
            assignment.Status = ArbiterStatusDisqualified
            log.Warn("arbiter disqualified mid-dispute",
                "nodeID", nodeID,
                "reason", reason)

            // IMPORTANT: Previous votes from this arbiter are VOIDED
            delete(committee.Votes, nodeID)

            // Select replacement from same VRF seed
            if err := SelectArbiterWithReplacement(committee); err != nil {
                return err
            }

            // New arbiter must review from start
            log.Info("new arbiter assigned, reviewing from start",
                "replacedNodeID", nodeID)

            return nil
        }
    }

    return ErrArbiterNotFound{NodeID: nodeID}
}

// CheckArbiterStake monitors stake balance during dispute
func CheckArbiterStake(committee *ArbiterCommittee) {
    for i := range committee.Assignments {
        assignment := &committee.Assignments[i]

        if assignment.Status != ArbiterStatusAccepted {
            continue
        }

        // Check stake balance
        stake, err := GetArbiterStake(assignment.NodeID)
        if err != nil {
            log.Error("failed to check arbiter stake", "error", err)
            continue
        }

        // If stake dropped below minimum, disqualify
        if stake < MinimumArbiterStake {
            ReplaceArbiterMidDispute(committee, assignment.NodeID,
                "stake below minimum")
        }
    }
}
```

#### VRF Selection Algorithm

```go
// SelectArbiterCommittee selects 7 arbiters via VRF (updated from 5)
func SelectArbiterCommittee(escrowID [32]byte) ([]NodeID, error) {
    // Generate VRF seed from escrow ID and current time
    seed := GenerateArbiterSeed(escrowID, time.Now().Unix())

    // Get all eligible arbiters
    candidates := GetEligibleArbiters(DefaultArbiterEligibility)
    if len(candidates) < ArbiterCommitteeSize {
        return nil, ErrInsufficientArbiters{
            Required:  ArbiterCommitteeSize,
            Available: len(candidates),
        }
    }

    // Select with diversity requirements
    return SelectWithDiversity(seed, candidates, ArbiterCommitteeSize)
}

// GenerateArbiterSeed creates deterministic, unpredictable seed
func GenerateArbiterSeed(escrowID [32]byte, timestamp int64) []byte {
    h := sha256.New()
    h.Write(escrowID[:])
    binary.Write(h, binary.BigEndian, timestamp)
    h.Write([]byte("arbiter_selection"))
    return h.Sum(nil)
}

// SelectWithDiversity ensures geographic and reputation diversity
func SelectWithDiversity(seed []byte, candidates []Node, count int) ([]NodeID, error) {
    // Evaluate VRF for each candidate
    results := make([]VRFResult, 0, len(candidates))
    for _, c := range candidates {
        output, proof := c.EvaluateVRF(seed)
        results = append(results, VRFResult{
            NodeID: c.ID,
            Output: output,
            Proof:  proof,
        })
    }

    // Sort by VRF output (deterministic ordering)
    sort.Slice(results, func(i, j int) bool {
        return bytes.Compare(results[i].Output, results[j].Output) < 0
    })

    // Apply diversity constraints
    selected := make([]NodeID, 0, count)
    regions := make(map[string]int)

    for _, r := range results {
        node := GetNodeByID(r.NodeID)

        // Max 2 from same region
        if regions[node.Region] >= 2 {
            continue
        }
        regions[node.Region]++

        selected = append(selected, r.NodeID)
        if len(selected) == count {
            break
        }
    }

    if len(selected) < count {
        return nil, ErrInsufficientDiversity
    }

    return selected, nil
}
```

#### Arbiter Voting

```go
// ArbiterVote represents an arbiter's decision
type ArbiterVote struct {
    EscrowID    [32]byte
    ArbiterID   NodeID
    Decision    DisputeOutcome  // Release, Refund, Split
    SplitRatio  float64         // If Split: 0.0-1.0 to seller
    Reasoning   string          // Required justification
    Evidence    [][32]byte      // References to evidence hashes
    Timestamp   int64
    Signature   []byte          // TPM-signed vote
}

type DisputeOutcome uint8
const (
    OutcomeRelease DisputeOutcome = 1  // Release to seller
    OutcomeRefund  DisputeOutcome = 2  // Refund to buyer
    OutcomeSplit   DisputeOutcome = 3  // Split between parties
)

// TallyVotes counts arbiter decisions (5-of-7 quorum per E1 fix)
func TallyVotes(votes []ArbiterVote) (*DisputeResolution, error) {
    if len(votes) < ArbiterQuorum {
        return nil, ErrInsufficientVotes{
            Required: ArbiterQuorum,
            Received: len(votes),
        }
    }

    // Count outcomes
    outcomes := make(map[DisputeOutcome]int)
    splitRatios := make([]float64, 0)

    for _, v := range votes {
        outcomes[v.Decision]++
        if v.Decision == OutcomeSplit {
            splitRatios = append(splitRatios, v.SplitRatio)
        }
    }

    // Find majority outcome
    var majority DisputeOutcome
    var majorityCount int
    for outcome, count := range outcomes {
        if count > majorityCount {
            majority = outcome
            majorityCount = count
        }
    }

    // Need 5-of-7 agreement (E1 fix: increased from 3-of-5)
    if majorityCount < ArbiterQuorum {
        return nil, ErrNoQuorum{
            Required:  ArbiterQuorum,
            BestCount: majorityCount,
        }
    }

    resolution := &DisputeResolution{
        Outcome:    majority,
        VoteCount:  majorityCount,
        TotalVotes: len(votes),
    }

    // If split, use median ratio
    if majority == OutcomeSplit && len(splitRatios) > 0 {
        sort.Float64s(splitRatios)
        resolution.SplitRatio = splitRatios[len(splitRatios)/2]
    }

    return resolution, nil
}

type DisputeResolution struct {
    Outcome     DisputeOutcome
    SplitRatio  float64  // Only if Outcome == OutcomeSplit
    VoteCount   int      // Number of agreeing arbiters
    TotalVotes  int      // Total votes cast
}
```

#### Arbiter Incentives

| Behavior | Consequence |
|----------|-------------|
| Correct judgment (matches majority) | +0.001 reputation |
| Minority judgment (matches minority) | No change |
| No vote within 72 hours | -0.01 reputation |
| Evidence of bribery/collusion | -0.5 reputation + ban |
| Consistent fair judgments | Priority for future selection |

---

## Service Completion Criteria

Service delivery and completion must be objectively verifiable to prevent disputes and enable fair escrow resolution.

### Completion Definition Framework

```go
// ServiceCompletionCriteria defines what constitutes "delivered"
type ServiceCompletionCriteria struct {
    ServiceType       ServiceType
    CompletionType    CompletionType
    ObjectiveMeasures []ObjectiveMeasure
    SubjectiveMeasures []SubjectiveMeasure
    VerificationMethod VerificationMethod
    AcceptanceWindow  time.Duration  // Buyer has this long to reject
}

// CompletionType categorizes how delivery is verified
type CompletionType uint8

const (
    // Objective completion - measurable, verifiable
    CompletionTypeObjective CompletionType = 1

    // Subjective completion - requires buyer acceptance
    CompletionTypeSubjective CompletionType = 2

    // Hybrid - mix of objective and subjective
    CompletionTypeHybrid CompletionType = 3
)

// ObjectiveMeasure defines measurable completion criteria
type ObjectiveMeasure struct {
    Name        string   // "uptime", "storage_gb", "response_time"
    Threshold   float64  // Required value
    Unit        string   // Measurement unit
    Verification string  // How to verify (e.g., "on-chain", "third_party_oracle")
}

// SubjectiveMeasure defines quality-based criteria
type SubjectiveMeasure struct {
    Name        string   // "visual_quality", "user_satisfaction"
    Description string   // Clear description of requirement
    Weight      float64  // Importance weight (0.0-1.0)
    MinAcceptable float64 // Minimum acceptable score (0.0-1.0)
}

// VerificationMethod determines who decides delivery
type VerificationMethod uint8

const (
    // Seller attestation + buyer acceptance window
    VerificationBuyerAcceptance VerificationMethod = 1

    // Automated on-chain verification
    VerificationAutomated VerificationMethod = 2

    // Third-party oracle verification
    VerificationOracle VerificationMethod = 3

    // Dual signature (both parties must sign)
    VerificationDualSignature VerificationMethod = 4
)
```

### Service-Type Specific Completion Rules

```go
// PresetCompletionCriteria defines standard criteria per service type
var PresetCompletionCriteria = map[ServiceType]ServiceCompletionCriteria{
    ServiceTypeHosting: {
        ServiceType:    ServiceTypeHosting,
        CompletionType: CompletionTypeObjective,
        ObjectiveMeasures: []ObjectiveMeasure{
            {
                Name:         "uptime_percentage",
                Threshold:    99.0,
                Unit:         "percent",
                Verification: "automated_monitoring",
            },
            {
                Name:         "response_time",
                Threshold:    500,
                Unit:         "milliseconds",
                Verification: "automated_monitoring",
            },
        },
        VerificationMethod: VerificationAutomated,
        AcceptanceWindow:   24 * time.Hour,
    },

    ServiceTypeStorage: {
        ServiceType:    ServiceTypeStorage,
        CompletionType: CompletionTypeObjective,
        ObjectiveMeasures: []ObjectiveMeasure{
            {
                Name:         "storage_provided",
                Threshold:    0,  // Must match contracted amount
                Unit:         "gigabytes",
                Verification: "on_chain_proof",
            },
            {
                Name:         "availability",
                Threshold:    99.9,
                Unit:         "percent",
                Verification: "automated_monitoring",
            },
        },
        VerificationMethod: VerificationAutomated,
        AcceptanceWindow:   24 * time.Hour,
    },

    ServiceTypeEcommerce: {
        ServiceType:    ServiceTypeEcommerce,
        CompletionType: CompletionTypeHybrid,
        ObjectiveMeasures: []ObjectiveMeasure{
            {
                Name:         "delivery_confirmed",
                Threshold:    1,  // Boolean
                Unit:         "boolean",
                Verification: "tracking_number_or_signature",
            },
        },
        SubjectiveMeasures: []SubjectiveMeasure{
            {
                Name:        "product_as_described",
                Description: "Product matches listing description",
                Weight:      0.6,
                MinAcceptable: 0.7,
            },
            {
                Name:        "product_condition",
                Description: "Product arrived undamaged and functional",
                Weight:      0.4,
                MinAcceptable: 0.8,
            },
        },
        VerificationMethod: VerificationBuyerAcceptance,
        AcceptanceWindow:   7 * 24 * time.Hour,  // 7 days for physical goods
    },

    ServiceTypeAPI: {
        ServiceType:    ServiceTypeAPI,
        CompletionType: CompletionTypeObjective,
        ObjectiveMeasures: []ObjectiveMeasure{
            {
                Name:         "request_count",
                Threshold:    0,  // Must match contracted amount
                Unit:         "requests",
                Verification: "on_chain_counter",
            },
            {
                Name:         "error_rate",
                Threshold:    1.0,  // Max 1% errors
                Unit:         "percent",
                Verification: "automated_monitoring",
            },
        },
        VerificationMethod: VerificationAutomated,
        AcceptanceWindow:   24 * time.Hour,
    },

    ServiceTypeCompute: {
        ServiceType:    ServiceTypeCompute,
        CompletionType: CompletionTypeObjective,
        ObjectiveMeasures: []ObjectiveMeasure{
            {
                Name:         "compute_hours",
                Threshold:    0,  // Must match contracted amount
                Unit:         "cpu_hours",
                Verification: "on_chain_proof",
            },
        },
        VerificationMethod: VerificationAutomated,
        AcceptanceWindow:   24 * time.Hour,
    },

    ServiceTypeCustom: {
        ServiceType:    ServiceTypeCustom,
        CompletionType: CompletionTypeHybrid,
        SubjectiveMeasures: []SubjectiveMeasure{
            {
                Name:        "service_satisfaction",
                Description: "Service meets agreed-upon requirements",
                Weight:      1.0,
                MinAcceptable: 0.7,
            },
        },
        VerificationMethod: VerificationBuyerAcceptance,
        AcceptanceWindow:   7 * 24 * time.Hour,
    },
}
```

### Completion Verification Protocol

```go
// VerifyCompletion checks if service meets completion criteria
func VerifyCompletion(
    order *Order,
    criteria *ServiceCompletionCriteria,
    deliveryProof *DeliveryProof,
) (*CompletionVerificationResult, error) {
    result := &CompletionVerificationResult{
        OrderID:    order.OrderID,
        Timestamp:  time.Now(),
        Criteria:   criteria,
    }

    // Verify objective measures
    for _, measure := range criteria.ObjectiveMeasures {
        verified, score := verifyObjectiveMeasure(order, measure, deliveryProof)
        result.ObjectiveScores = append(result.ObjectiveScores, MeasureScore{
            Measure:  measure.Name,
            Score:    score,
            Passed:   verified,
        })

        if !verified {
            result.Passed = false
            result.FailureReasons = append(result.FailureReasons,
                fmt.Sprintf("objective measure '%s' failed: %.2f < %.2f",
                    measure.Name, score, measure.Threshold))
        }
    }

    // Verify subjective measures (if applicable)
    for _, measure := range criteria.SubjectiveMeasures {
        score := getSubjectiveMeasureScore(order, measure)
        result.SubjectiveScores = append(result.SubjectiveScores, MeasureScore{
            Measure: measure.Name,
            Score:   score,
            Passed:  score >= measure.MinAcceptable,
        })

        if score < measure.MinAcceptable {
            result.Passed = false
            result.FailureReasons = append(result.FailureReasons,
                fmt.Sprintf("subjective measure '%s' failed: %.2f < %.2f",
                    measure.Name, score, measure.MinAcceptable))
        }
    }

    // If all measures pass, service is complete
    if len(result.FailureReasons) == 0 {
        result.Passed = true
    }

    return result, nil
}

// CompletionVerificationResult contains verification outcome
type CompletionVerificationResult struct {
    OrderID          [32]byte
    Timestamp        time.Time
    Criteria         *ServiceCompletionCriteria
    ObjectiveScores  []MeasureScore
    SubjectiveScores []MeasureScore
    Passed           bool
    FailureReasons   []string
}

type MeasureScore struct {
    Measure string
    Score   float64
    Passed  bool
}
```

### Who Decides Completion

```go
// CompletionDecisionAuthority determines who has final say
func CompletionDecisionAuthority(criteria *ServiceCompletionCriteria) string {
    switch criteria.VerificationMethod {
    case VerificationAutomated:
        return "automated_system"
        // Automated metrics decide (uptime, storage, CPU hours)
        // No human intervention needed

    case VerificationBuyerAcceptance:
        return "buyer"
        // Buyer must explicitly accept delivery
        // Silence within acceptance window = auto-accept

    case VerificationDualSignature:
        return "both_parties"
        // Both buyer and seller must sign
        // Used for high-value or complex services

    case VerificationOracle:
        return "third_party_oracle"
        // Trusted third-party oracle decides
        // Used for external verification needs

    default:
        return "unknown"
    }
}

// AcceptanceWindowBehavior defines what happens if buyer doesn't respond
const (
    // DefaultAcceptanceWindow is the standard window for buyer acceptance
    DefaultAcceptanceWindow = 7 * 24 * time.Hour  // 7 days

    // After acceptance window expires without buyer rejection:
    // - Service is considered accepted
    // - Escrow enters dispute window (48 hours)
    // - Buyer can still dispute within dispute window
)
```

---

## Partial Delivery Handling

Partial delivery occurs when a seller provides only a portion of the agreed service or goods.

### Partial Delivery Thresholds

```go
// PartialDeliveryPolicy defines how partial delivery is handled
type PartialDeliveryPolicy struct {
    MinimumAcceptableCompletion float64      // Minimum % to avoid auto-refund
    PartialRefundFormula        RefundFormula
    DisputeThreshold            float64      // % below which dispute auto-opens
    EvidenceRequirements        []string
}

// RefundFormula calculates refund amount based on completion %
type RefundFormula uint8

const (
    // Linear: refund = (1 - completion_percent) * escrow_amount
    RefundFormulaLinear RefundFormula = 1

    // Stepped: predefined tiers (e.g., <50% = full refund, 50-75% = 50% refund)
    RefundFormulaStepped RefundFormula = 2

    // Custom: contract-specific formula
    RefundFormulaCustom RefundFormula = 3
)

// Default policy applies if not specified in contract
var DefaultPartialDeliveryPolicy = PartialDeliveryPolicy{
    MinimumAcceptableCompletion: 0.80,  // 80%
    PartialRefundFormula:        RefundFormulaLinear,
    DisputeThreshold:            0.50,  // <50% = auto-dispute
    EvidenceRequirements: []string{
        "delivery_proof",
        "completion_metrics",
        "buyer_acknowledgment",
    },
}
```

### Partial Delivery Classification

```go
// PartialDeliveryLevel categorizes severity
type PartialDeliveryLevel uint8

const (
    // Near-complete: 90-99% delivered
    PartialDeliveryNearComplete PartialDeliveryLevel = 1

    // Substantial: 70-89% delivered
    PartialDeliverySubstantial PartialDeliveryLevel = 2

    // Partial: 50-69% delivered
    PartialDeliveryPartial PartialDeliveryLevel = 3

    // Minimal: 25-49% delivered
    PartialDeliveryMinimal PartialDeliveryLevel = 4

    // Negligible: <25% delivered
    PartialDeliveryNegligible PartialDeliveryLevel = 5
)

// ClassifyPartialDelivery determines severity level
func ClassifyPartialDelivery(completionPercent float64) PartialDeliveryLevel {
    switch {
    case completionPercent >= 0.90:
        return PartialDeliveryNearComplete
    case completionPercent >= 0.70:
        return PartialDeliverySubstantial
    case completionPercent >= 0.50:
        return PartialDeliveryPartial
    case completionPercent >= 0.25:
        return PartialDeliveryMinimal
    default:
        return PartialDeliveryNegligible
    }
}
```

### Partial Delivery Resolution

```go
// HandlePartialDelivery processes partial delivery scenarios
func HandlePartialDelivery(
    escrow *Escrow,
    completionPercent float64,
    evidence *PartialDeliveryEvidence,
) (*PartialDeliveryResolution, error) {
    policy := GetPartialDeliveryPolicy(escrow)
    level := ClassifyPartialDelivery(completionPercent)

    resolution := &PartialDeliveryResolution{
        EscrowID:          escrow.EscrowID,
        CompletionPercent: completionPercent,
        Level:             level,
        Policy:            policy,
    }

    // Calculate refund based on formula
    switch policy.PartialRefundFormula {
    case RefundFormulaLinear:
        // Linear: buyer gets back (1 - completion_percent) * escrow_amount
        // Seller gets completion_percent * escrow_amount
        refundAmount := uint64(float64(escrow.Amount) * (1.0 - completionPercent))
        sellerAmount := escrow.Amount - refundAmount

        resolution.RefundAmount = refundAmount
        resolution.SellerAmount = sellerAmount

    case RefundFormulaStepped:
        // Stepped tiers
        switch level {
        case PartialDeliveryNearComplete:
            // 90-99%: seller gets 95%, buyer gets 5% refund
            resolution.SellerAmount = escrow.Amount * 95 / 100
            resolution.RefundAmount = escrow.Amount * 5 / 100

        case PartialDeliverySubstantial:
            // 70-89%: proportional split
            resolution.SellerAmount = uint64(float64(escrow.Amount) * completionPercent)
            resolution.RefundAmount = escrow.Amount - resolution.SellerAmount

        case PartialDeliveryPartial:
            // 50-69%: buyer gets 60%, seller gets 40%
            resolution.RefundAmount = escrow.Amount * 60 / 100
            resolution.SellerAmount = escrow.Amount * 40 / 100

        case PartialDeliveryMinimal:
            // 25-49%: buyer gets 80%, seller gets 20%
            resolution.RefundAmount = escrow.Amount * 80 / 100
            resolution.SellerAmount = escrow.Amount * 20 / 100

        case PartialDeliveryNegligible:
            // <25%: full refund to buyer
            resolution.RefundAmount = escrow.Amount
            resolution.SellerAmount = 0
        }
    }

    // Auto-dispute if below threshold
    if completionPercent < policy.DisputeThreshold {
        resolution.RequiresDispute = true
        resolution.DisputeReason = fmt.Sprintf(
            "completion %.1f%% below threshold %.1f%%",
            completionPercent*100, policy.DisputeThreshold*100)
    }

    return resolution, nil
}

// PartialDeliveryResolution contains resolution outcome
type PartialDeliveryResolution struct {
    EscrowID          [32]byte
    CompletionPercent float64
    Level             PartialDeliveryLevel
    Policy            PartialDeliveryPolicy
    RefundAmount      uint64
    SellerAmount      uint64
    RequiresDispute   bool
    DisputeReason     string
}

// PartialDeliveryEvidence documents what was delivered
type PartialDeliveryEvidence struct {
    ItemsOrdered     []OrderItem       // Full order
    ItemsDelivered   []OrderItem       // What was actually delivered
    MetricsAchieved  map[string]float64 // Objective metrics
    BuyerAttestation []byte            // Buyer's signed statement
    SellerAttestation []byte           // Seller's signed statement
    Timestamp        time.Time
}
```

### Partial Completion Example Scenarios

```
Scenario 1: Hosting service with 95% uptime (contracted 99%)
- CompletionPercent: 95%
- Level: PartialDeliveryNearComplete
- Resolution: Seller gets 95% of escrow, buyer gets 5% refund
- Dispute: No (above 80% threshold)

Scenario 2: Storage service delivering 60GB of 100GB contracted
- CompletionPercent: 60%
- Level: PartialDeliveryPartial
- Resolution: Buyer gets 40% refund, seller gets 60%
- Dispute: No (above 50% threshold)

Scenario 3: E-commerce order with 4 of 10 items delivered
- CompletionPercent: 40%
- Level: PartialDeliveryMinimal
- Resolution: Buyer gets 60% refund, seller gets 40%
- Dispute: Yes (below 50% threshold - auto-dispute opens)

Scenario 4: API service with 15% of contracted requests fulfilled
- CompletionPercent: 15%
- Level: PartialDeliveryNegligible
- Resolution: Full refund to buyer, seller gets nothing
- Dispute: Yes (below 50% threshold - auto-dispute opens)
```

---

## Quality Dispute Procedures

Quality disputes arise when delivery is technically complete but quality is contested.

### Quality Metrics Framework

```go
// QualityMetric defines measurable quality criteria
type QualityMetric struct {
    Name           string
    Type           QualityMetricType
    Measurement    string        // How it's measured
    ObjectiveProof []string      // Required proof types
    Weight         float64       // Importance (0.0-1.0)
}

// QualityMetricType categorizes quality measures
type QualityMetricType uint8

const (
    // Objective: measurable, verifiable (e.g., resolution, speed, accuracy)
    QualityMetricObjective QualityMetricType = 1

    // Subjective: opinion-based (e.g., design aesthetics, user experience)
    QualityMetricSubjective QualityMetricType = 2

    // Industry standard: compare against established benchmarks
    QualityMetricIndustryStandard QualityMetricType = 3
)
```

### Quality Evidence Requirements

```go
// QualityEvidence contains proof for quality claims
type QualityEvidence struct {
    Claim           string          // What is being claimed
    EvidenceType    EvidenceType
    Proof           []byte          // Evidence data
    Timestamp       time.Time
    SubmittedBy     [32]byte        // NodeID of submitter
    Signature       []byte          // TPM signature
    ExpertReview    *ExpertReview   // Optional expert analysis
}

// EvidenceType categorizes quality evidence
type EvidenceType uint8

const (
    EvidenceTypePhotograph       EvidenceType = 1  // Photos of product
    EvidenceTypeScreenshot       EvidenceType = 2  // Software screenshots
    EvidenceTypeVideo            EvidenceType = 3  // Video documentation
    EvidenceTypeMetrics          EvidenceType = 4  // Performance metrics
    EvidenceTypeBenchmark        EvidenceType = 5  // Benchmark results
    EvidenceTypeThirdPartyReport EvidenceType = 6  // External assessment
    EvidenceTypeUserTestimony    EvidenceType = 7  // User feedback
    EvidenceTypeComparison       EvidenceType = 8  // Side-by-side comparison
)

// Quality evidence must meet minimum standards
const (
    MinPhotographResolution = 1920 * 1080  // 1080p minimum
    MinVideoLength         = 30             // 30 seconds minimum
    MinBenchmarkSamples    = 100            // 100+ data points
    RequireTimestamp       = true           // All evidence must be timestamped
)
```

### Quality Arbiter Qualifications

```go
// QualityArbiterRequirements defines specialized arbiter needs
type QualityArbiterRequirements struct {
    BaseRequirements  ArbiterEligibility
    DomainExpertise   []string         // Required expertise areas
    MinQualityDisputes int              // Minimum past quality disputes handled
    SpecializationProof []byte          // Proof of expertise (certifications, etc.)
}

// SelectQualityArbiter chooses arbiter with domain expertise
func SelectQualityArbiter(
    dispute *QualityDispute,
    requiredExpertise []string,
) (*ArbiterAssignment, error) {
    // Filter candidates by domain expertise
    candidates := GetEligibleArbiters(DefaultArbiterEligibility)

    qualifiedArbiters := []Node{}
    for _, candidate := range candidates {
        if hasRequiredExpertise(candidate, requiredExpertise) {
            qualifiedArbiters = append(qualifiedArbiters, candidate)
        }
    }

    if len(qualifiedArbiters) == 0 {
        // No domain experts available - escalate to expert witness process
        return nil, ErrNoQualifiedArbiters{
            RequiredExpertise: requiredExpertise,
            Action:           "escalating_to_expert_witness",
        }
    }

    // Select arbiter via VRF from qualified pool
    seed := GenerateArbiterSeed(dispute.EscrowID, time.Now().Unix())
    selected, err := SelectWithDiversity(seed, qualifiedArbiters, 1)
    if err != nil {
        return nil, err
    }

    return &ArbiterAssignment{
        NodeID:     selected[0],
        AssignedAt: time.Now(),
        Status:     ArbiterStatusPending,
    }, nil
}

// hasRequiredExpertise checks if arbiter has domain knowledge
func hasRequiredExpertise(arbiter Node, requiredExpertise []string) bool {
    for _, expertise := range requiredExpertise {
        if !contains(arbiter.Expertise, expertise) {
            return false
        }
    }
    return true
}
```

### Quality Dispute Resolution Process

```go
// QualityDispute represents a quality-based dispute
type QualityDispute struct {
    EscrowID         [32]byte
    DisputedAspects  []QualityAspect
    BuyerEvidence    []QualityEvidence
    SellerEvidence   []QualityEvidence
    RequiredExpertise []string
    ExpertWitness    *ExpertWitness  // If needed
    Status           DisputeStatus
    FiledAt          time.Time
}

// QualityAspect identifies specific quality issue
type QualityAspect struct {
    Name             string
    Expected         string  // What was promised
    Actual           string  // What was delivered
    MetricType       QualityMetricType
    BuyerAssessment  float64  // Buyer's quality rating (0.0-1.0)
    SellerAssessment float64  // Seller's quality rating (0.0-1.0)
}

// ResolveQualityDispute handles quality-based arbitration
func ResolveQualityDispute(dispute *QualityDispute) (*DisputeResolution, error) {
    // Collect all evidence
    allEvidence := append(dispute.BuyerEvidence, dispute.SellerEvidence...)

    // Determine if expert witness is needed
    needsExpert := requiresExpertWitness(dispute)
    if needsExpert && dispute.ExpertWitness == nil {
        return nil, ErrExpertWitnessRequired{
            DisputeID: dispute.EscrowID,
            Reason:   "subjective quality dispute requires expert opinion",
        }
    }

    // Score each quality aspect
    scores := make(map[string]float64)
    for _, aspect := range dispute.DisputedAspects {
        score := scoreQualityAspect(aspect, allEvidence, dispute.ExpertWitness)
        scores[aspect.Name] = score
    }

    // Calculate overall quality score
    overallScore := calculateWeightedScore(scores, dispute.DisputedAspects)

    // Determine outcome based on overall score
    var outcome DisputeOutcome
    var splitRatio float64

    switch {
    case overallScore >= 0.80:
        // High quality - seller wins
        outcome = OutcomeRelease

    case overallScore >= 0.60:
        // Acceptable quality - mostly to seller
        outcome = OutcomeSplit
        splitRatio = 0.80  // 80% to seller, 20% to buyer

    case overallScore >= 0.40:
        // Below acceptable - split
        outcome = OutcomeSplit
        splitRatio = 0.50  // 50/50 split

    case overallScore >= 0.20:
        // Poor quality - mostly to buyer
        outcome = OutcomeSplit
        splitRatio = 0.20  // 20% to seller, 80% to buyer

    default:
        // Unacceptable quality - buyer wins
        outcome = OutcomeRefund
    }

    return &DisputeResolution{
        Outcome:     outcome,
        SplitRatio:  splitRatio,
        Reasoning:   fmt.Sprintf("overall quality score: %.2f", overallScore),
    }, nil
}

// requiresExpertWitness determines if expert opinion is needed
func requiresExpertWitness(dispute *QualityDispute) bool {
    // Expert needed if:
    // 1. Majority of aspects are subjective
    // 2. High-value dispute (>10,000 coins)
    // 3. Complex technical domain
    // 4. Large gap between buyer and seller assessments

    subjectiveCount := 0
    for _, aspect := range dispute.DisputedAspects {
        if aspect.MetricType == QualityMetricSubjective {
            subjectiveCount++
        }
    }

    majoritySubjective := float64(subjectiveCount) / float64(len(dispute.DisputedAspects)) > 0.5

    // Check for large assessment gaps
    largeGap := false
    for _, aspect := range dispute.DisputedAspects {
        gap := math.Abs(aspect.BuyerAssessment - aspect.SellerAssessment)
        if gap > 0.4 {  // >40% disagreement
            largeGap = true
            break
        }
    }

    return majoritySubjective || largeGap
}
```

---

## Expert Witness Procedures

Expert witnesses provide specialized knowledge for complex disputes.

### Expert Witness Eligibility

```go
// ExpertWitnessQualifications defines requirements to serve as expert
type ExpertWitnessQualifications struct {
    BaseRequirements  ArbiterEligibility
    DomainExpertise   string         // Specific domain (e.g., "software_architecture")
    YearsExperience   int            // Minimum years in domain
    Certifications    []string       // Professional certifications
    PastCases         int            // Minimum cases as expert
    PeerEndorsements  int            // Endorsements from other experts
    EducationProof    []byte         // Educational credentials
}

// Minimum expert witness requirements
const (
    MinExpertYearsExperience  = 5
    MinExpertPastCases        = 10
    MinExpertPeerEndorsements = 3
    MinExpertReputation       = 0.85
)
```

### Expert Witness Selection Protocol

```go
// SelectExpertWitness chooses expert for dispute
func SelectExpertWitness(
    dispute *QualityDispute,
    domain string,
) (*ExpertWitness, error) {
    // Get all qualified experts in domain
    candidates := GetQualifiedExperts(domain)

    if len(candidates) == 0 {
        return nil, ErrNoQualifiedExperts{
            Domain: domain,
            Action: "dispute cannot proceed without expert",
        }
    }

    // VRF selection from expert pool
    seed := GenerateExpertSeed(dispute.EscrowID, domain, time.Now().Unix())
    selected, err := SelectWithDiversity(seed, candidates, 1)
    if err != nil {
        return nil, err
    }

    expert := &ExpertWitness{
        NodeID:        selected[0],
        Domain:        domain,
        AssignedAt:    time.Now(),
        AcceptDeadline: time.Now().Add(48 * time.Hour),
        Status:        ExpertStatusPending,
    }

    // Notify expert of assignment
    NotifyExpert(expert.NodeID, &ExpertAssignmentNotification{
        DisputeID:      dispute.EscrowID,
        Domain:         domain,
        AcceptDeadline: expert.AcceptDeadline,
        CompensationFee: CalculateExpertFee(dispute),
    })

    return expert, nil
}

// ExpertWitness represents assigned expert
type ExpertWitness struct {
    NodeID          [32]byte
    Domain          string
    AssignedAt      time.Time
    AcceptDeadline  time.Time
    AcceptedAt      *time.Time
    Status          ExpertStatus
    Testimony       *ExpertTestimony
    CompensationFee uint64
}

// ExpertStatus tracks expert participation
type ExpertStatus uint8

const (
    ExpertStatusPending   ExpertStatus = 0  // Awaiting acceptance
    ExpertStatusAccepted  ExpertStatus = 1  // Accepted assignment
    ExpertStatusRefused   ExpertStatus = 2  // Refused assignment
    ExpertStatusDelivered ExpertStatus = 3  // Testimony submitted
)
```

### Expert Testimony Format

```go
// ExpertTestimony contains expert's analysis
type ExpertTestimony struct {
    ExpertID        [32]byte
    DisputeID       [32]byte
    Domain          string

    // Analysis
    Summary         string          // Executive summary
    Findings        []Finding       // Detailed findings
    QualityScore    float64         // Overall quality assessment (0.0-1.0)
    Recommendation  DisputeOutcome  // Recommended outcome
    SplitRatio      float64         // If split recommended

    // Supporting evidence
    Methodology     string          // How analysis was performed
    References      []string        // Industry standards, benchmarks
    Attachments     [][32]byte      // Evidence hashes

    // Metadata
    SubmittedAt     time.Time
    TimeSpent       time.Duration   // Time spent on analysis
    Signature       []byte          // TPM signature
}

// Finding represents a specific expert observation
type Finding struct {
    Aspect          string    // What was examined
    Expected        string    // Industry standard or contract requirement
    Observed        string    // What was actually found
    Assessment      string    // Expert's evaluation
    Score           float64   // Quality score for this aspect (0.0-1.0)
    CitedStandards  []string  // Referenced standards
}

// Expert testimony requirements
const (
    MinTestimonySummaryLength = 200   // Minimum 200 characters
    MinFindingsCount          = 3     // At least 3 detailed findings
    RequireMethodology        = true   // Methodology must be explained
    RequireReferences         = true   // Must cite standards/benchmarks
    MaxTestimonyDeliveryTime  = 7 * 24 * time.Hour  // 7 days max
)
```

### When Expert Witnesses Are Required

```go
// ExpertWitnessRequirementPolicy defines when experts are needed
type ExpertWitnessRequirementPolicy struct {
    HighValueThreshold    uint64   // Escrow amount requiring expert
    SubjectiveRatio       float64  // % subjective criteria requiring expert
    TechnicalComplexity   []string // Domains always requiring expert
    LargeDisagreementGap  float64  // Assessment gap requiring expert
}

var DefaultExpertWitnessPolicy = ExpertWitnessRequirementPolicy{
    HighValueThreshold:   20000,  // >20,000 coins
    SubjectiveRatio:      0.60,   // >60% subjective
    TechnicalComplexity: []string{
        "software_architecture",
        "hardware_engineering",
        "medical_services",
        "legal_services",
        "financial_services",
    },
    LargeDisagreementGap: 0.40,   // >40% gap
}

// RequiresExpertWitness determines if expert is mandatory
func RequiresExpertWitness(dispute *QualityDispute, escrow *Escrow) bool {
    policy := DefaultExpertWitnessPolicy

    // Check high value
    if escrow.Amount >= policy.HighValueThreshold {
        return true
    }

    // Check subjective ratio
    subjectiveCount := 0
    for _, aspect := range dispute.DisputedAspects {
        if aspect.MetricType == QualityMetricSubjective {
            subjectiveCount++
        }
    }
    ratio := float64(subjectiveCount) / float64(len(dispute.DisputedAspects))
    if ratio >= policy.SubjectiveRatio {
        return true
    }

    // Check technical complexity
    for _, domain := range policy.TechnicalComplexity {
        if dispute.RequiredExpertise != nil && contains(dispute.RequiredExpertise, domain) {
            return true
        }
    }

    // Check disagreement gap
    for _, aspect := range dispute.DisputedAspects {
        gap := math.Abs(aspect.BuyerAssessment - aspect.SellerAssessment)
        if gap >= policy.LargeDisagreementGap {
            return true
        }
    }

    return false
}
```

### Expert Compensation

```go
// CalculateExpertFee determines expert witness payment
func CalculateExpertFee(dispute *QualityDispute, escrow *Escrow) uint64 {
    // Base fee: 2% of escrow amount
    baseFee := escrow.Amount * 2 / 100

    // Minimum fee: 100 coins
    minFee := uint64(100)

    // Maximum fee: 1000 coins
    maxFee := uint64(1000)

    fee := max(baseFee, minFee)
    fee = min(fee, maxFee)

    // Expert fee is paid from escrow before distribution
    // Deducted from losing party's share (or split 50/50 if split outcome)

    return fee
}

// ExpertFeeAllocation determines who pays expert fee
func ExpertFeeAllocation(resolution *DisputeResolution) (buyerShare, sellerShare uint64, fee uint64) {
    switch resolution.Outcome {
    case OutcomeRelease:
        // Seller wins - buyer pays expert fee
        return fee, 0, fee

    case OutcomeRefund:
        // Buyer wins - seller pays expert fee
        return 0, fee, fee

    case OutcomeSplit:
        // Split outcome - both parties split expert fee
        return fee / 2, fee / 2, fee

    default:
        return 0, 0, 0
    }
}
```

---

## Appeal Process After Arbiter Decision

Parties may appeal arbiter decisions under specific conditions.

### Appeal Eligibility

```go
// AppealEligibility defines when appeals are allowed
type AppealEligibility struct {
    AppealWindow      time.Duration  // Window to file appeal
    RequireNewEvidence bool          // Must provide new evidence
    RequireProceduralError bool      // Or demonstrate procedural error
    MaxAppealRounds   int            // Maximum number of appeals
    MinEscrowValue    uint64         // Minimum escrow value for appeals
}

var DefaultAppealEligibility = AppealEligibility{
    AppealWindow:          72 * time.Hour,  // 72 hours from decision
    RequireNewEvidence:    true,
    RequireProceduralError: true,
    MaxAppealRounds:       2,  // Original + 1 appeal + 1 final appeal
    MinEscrowValue:        1000,  // No appeals for <1000 coins
}
```

### Appeal Requirements

```go
// AppealRequest represents a party's appeal
type AppealRequest struct {
    DisputeID         [32]byte
    OriginalDecision  *DisputeResolution
    AppellantID       [32]byte        // Who is appealing
    AppealRound       int              // 1 = first appeal, 2 = final
    FiledAt           time.Time

    // Grounds for appeal
    AppealGrounds     AppealGrounds
    NewEvidence       []QualityEvidence  // If based on new evidence
    ProceduralErrors  []ProceduralError  // If based on errors

    // Fee
    AppealFee         uint64           // Deposit to discourage frivolous appeals
    AppealFeeRefundable bool           // Refunded if appeal succeeds

    Signature         []byte           // TPM signature
}

// AppealGrounds categorizes reason for appeal
type AppealGrounds uint8

const (
    // New evidence discovered after decision
    AppealGroundsNewEvidence AppealGrounds = 1

    // Procedural error in dispute process
    AppealGroundsProceduralError AppealGrounds = 2

    // Arbiter bias or conflict of interest
    AppealGroundsArbiterBias AppealGrounds = 3

    // Manifestly incorrect decision (high bar)
    AppealGroundsClearError AppealGrounds = 4
)

// ProceduralError documents process violations
type ProceduralError struct {
    ErrorType     string   // Type of error
    Description   string   // What went wrong
    Impact        string   // How it affected outcome
    Evidence      []byte   // Proof of error
}
```

### Appeal Committee Composition

```go
// AppealCommittee handles appeals with higher authority
type AppealCommittee struct {
    DisputeID         [32]byte
    AppealRound       int
    CommitteeSize     int              // Larger than original
    QuorumSize        int              // Higher threshold
    Members           []AppealJudge
    ChairID           [32]byte         // Committee chair
    OriginalArbiters  [][32]byte       // Cannot serve on appeal
}

// AppealJudge has higher qualifications than regular arbiter
type AppealJudge struct {
    NodeID            [32]byte
    Reputation        float64          // Min 0.90 (higher than arbiter)
    PastDisputes      int              // Min 50 resolved disputes
    AppealExperience  int              // Min 10 appeals handled
    Seniority         time.Duration    // Min 1 year on network
    Specialization    string           // Domain expertise
}

// SelectAppealCommittee chooses appeal judges
func SelectAppealCommittee(
    dispute *Dispute,
    appeal *AppealRequest,
    originalArbiters [][32]byte,
) (*AppealCommittee, error) {
    // Appeal committee is larger and more experienced
    var committeeSize, quorumSize int

    switch appeal.AppealRound {
    case 1:
        // First appeal: 9 judges, 6-of-9 quorum
        committeeSize = 9
        quorumSize = 6

    case 2:
        // Final appeal: 11 judges, 8-of-11 quorum
        committeeSize = 11
        quorumSize = 8

    default:
        return nil, ErrInvalidAppealRound{Round: appeal.AppealRound}
    }

    // Get qualified appeal judges
    candidates := GetQualifiedAppealJudges()

    // Exclude original arbiters (conflict of interest)
    excludeSet := make(map[[32]byte]bool)
    for _, arbiterID := range originalArbiters {
        excludeSet[arbiterID] = true
    }

    // VRF selection
    seed := GenerateAppealSeed(dispute.EscrowID, appeal.AppealRound, time.Now().Unix())
    selected, err := SelectWithDiversityAndSkip(seed, candidates, committeeSize, excludeSet)
    if err != nil {
        return nil, err
    }

    // First selected judge becomes chair
    committee := &AppealCommittee{
        DisputeID:        dispute.EscrowID,
        AppealRound:      appeal.AppealRound,
        CommitteeSize:    committeeSize,
        QuorumSize:       quorumSize,
        ChairID:          selected[0],
        OriginalArbiters: originalArbiters,
    }

    // Populate members
    for _, judgeID := range selected {
        judge := GetAppealJudge(judgeID)
        committee.Members = append(committee.Members, judge)
    }

    return committee, nil
}

// Appeal judge minimum qualifications
const (
    MinAppealJudgeReputation    = 0.90
    MinAppealJudgePastDisputes  = 50
    MinAppealJudgeExperience    = 10  // Appeals handled
    MinAppealJudgeSeniority     = 365 * 24 * time.Hour  // 1 year
)
```

### Appeal Decision Process

```go
// AppealDecision represents committee's ruling
type AppealDecision struct {
    DisputeID         [32]byte
    AppealRound       int
    Decision          AppealOutcome
    Reasoning         string
    VoteBreakdown     map[AppealOutcome]int
    QuorumReached     bool
    NewResolution     *DisputeResolution  // If decision changed
    AppealFeeRefund   bool                // Whether fee is refunded
    DecidedAt         time.Time
    CommitteeSignatures [][]byte
}

// AppealOutcome categorizes appeal result
type AppealOutcome uint8

const (
    // Original decision upheld
    AppealOutcomeUpheld AppealOutcome = 1

    // Decision modified (new resolution)
    AppealOutcomeModified AppealOutcome = 2

    // Decision reversed (opposite outcome)
    AppealOutcomeReversed AppealOutcome = 3

    // Remanded back to original arbiters for reconsideration
    AppealOutcomeRemanded AppealOutcome = 4
)

// ProcessAppeal handles appeal review and decision
func ProcessAppeal(
    dispute *Dispute,
    appeal *AppealRequest,
    committee *AppealCommittee,
) (*AppealDecision, error) {
    // Validate appeal meets requirements
    if err := ValidateAppeal(appeal); err != nil {
        return nil, err
    }

    // Committee reviews:
    // 1. Original decision
    // 2. Original evidence
    // 3. New evidence (if provided)
    // 4. Procedural error claims (if raised)

    // Each judge casts vote
    votes := make(map[AppealOutcome]int)
    for _, judge := range committee.Members {
        vote := judge.CastAppealVote(appeal, dispute)
        votes[vote.Outcome]++
    }

    // Determine majority outcome
    var majorityOutcome AppealOutcome
    var maxVotes int
    for outcome, count := range votes {
        if count > maxVotes {
            majorityOutcome = outcome
            maxVotes = count
        }
    }

    // Check if quorum reached
    quorumReached := maxVotes >= committee.QuorumSize

    if !quorumReached {
        // No quorum - original decision stands, no fee refund
        return &AppealDecision{
            DisputeID:       dispute.EscrowID,
            AppealRound:     appeal.AppealRound,
            Decision:        AppealOutcomeUpheld,
            Reasoning:       "appeal committee failed to reach quorum",
            VoteBreakdown:   votes,
            QuorumReached:   false,
            AppealFeeRefund: false,
            DecidedAt:       time.Now(),
        }, nil
    }

    // Determine new resolution if decision changed
    var newResolution *DisputeResolution
    var feeRefund bool

    switch majorityOutcome {
    case AppealOutcomeUpheld:
        // Original decision stands, no fee refund
        newResolution = dispute.Resolution
        feeRefund = false

    case AppealOutcomeModified:
        // Partial change, partial fee refund (50%)
        newResolution = calculateModifiedResolution(dispute, appeal, committee)
        feeRefund = true  // 50% refund

    case AppealOutcomeReversed:
        // Complete reversal, full fee refund
        newResolution = reverseResolution(dispute.Resolution)
        feeRefund = true  // 100% refund

    case AppealOutcomeRemanded:
        // Send back to original arbiters, full fee refund
        newResolution = nil  // Will be decided by original arbiters
        feeRefund = true  // 100% refund
    }

    return &AppealDecision{
        DisputeID:           dispute.EscrowID,
        AppealRound:         appeal.AppealRound,
        Decision:            majorityOutcome,
        Reasoning:           generateAppealReasoning(committee, votes),
        VoteBreakdown:       votes,
        QuorumReached:       true,
        NewResolution:       newResolution,
        AppealFeeRefund:     feeRefund,
        DecidedAt:           time.Now(),
        CommitteeSignatures: collectCommitteeSignatures(committee),
    }, nil
}
```

### Maximum Appeal Rounds

```go
// Appeal round limits
const (
    MaxAppealRounds = 2  // Original decision + 1 appeal + 1 final appeal
)

// FileAppeal validates and submits appeal
func FileAppeal(
    dispute *Dispute,
    appellant [32]byte,
    grounds AppealGrounds,
    newEvidence []QualityEvidence,
    proceduralErrors []ProceduralError,
) (*AppealRequest, error) {
    // Check if within appeal window
    timeSinceDecision := time.Since(dispute.ResolvedAt)
    if timeSinceDecision > DefaultAppealEligibility.AppealWindow {
        return nil, ErrAppealWindowExpired{
            TimeSinceDecision: timeSinceDecision,
            WindowDuration:    DefaultAppealEligibility.AppealWindow,
        }
    }

    // Check if max appeals reached
    if dispute.AppealCount >= MaxAppealRounds {
        return nil, ErrMaxAppealsReached{
            CurrentCount: dispute.AppealCount,
            MaxAllowed:   MaxAppealRounds,
        }
    }

    // Validate grounds
    if grounds == AppealGroundsNewEvidence && len(newEvidence) == 0 {
        return nil, ErrMissingNewEvidence
    }
    if grounds == AppealGroundsProceduralError && len(proceduralErrors) == 0 {
        return nil, ErrMissingProceduralErrors
    }

    // Calculate appeal fee (increases with each round)
    appealFee := CalculateAppealFee(dispute, dispute.AppealCount+1)

    appeal := &AppealRequest{
        DisputeID:        dispute.EscrowID,
        OriginalDecision: dispute.Resolution,
        AppellantID:      appellant,
        AppealRound:      dispute.AppealCount + 1,
        FiledAt:          time.Now(),
        AppealGrounds:    grounds,
        NewEvidence:      newEvidence,
        ProceduralErrors: proceduralErrors,
        AppealFee:        appealFee,
        AppealFeeRefundable: true,
    }

    return appeal, nil
}

// CalculateAppealFee determines fee based on round and escrow value
func CalculateAppealFee(dispute *Dispute, round int) uint64 {
    // Base fee: 5% of escrow
    baseFee := dispute.Escrow.Amount * 5 / 100

    // Multiply by round (1st appeal = 5%, 2nd appeal = 10%)
    fee := baseFee * uint64(round)

    // Minimum: 50 coins
    minFee := uint64(50)

    // Maximum: 500 coins
    maxFee := uint64(500)

    fee = max(fee, minFee)
    fee = min(fee, maxFee)

    return fee
}
```

---

## Escrow Fee Structure

All escrow transactions incur fees to cover arbiter compensation and system maintenance.

### Escrow Fee Breakdown

```go
// EscrowFees defines all fees associated with an escrow
type EscrowFees struct {
    // Creation fee (paid by buyer when creating escrow)
    CreationFee       uint64

    // Arbiter fees (paid if dispute occurs)
    ArbiterBaseFee    uint64   // Base arbiter compensation
    ArbiterPerVoteFee uint64   // Per-arbiter voting fee
    ExpertWitnessFee  uint64   // Expert witness fee (if used)

    // Appeal fees (paid by appellant)
    AppealFee         uint64

    // Network maintenance fee
    NetworkFee        uint64   // Percentage to network treasury

    // Total fees
    TotalFees         uint64
}

// CalculateEscrowFees computes all fees for an escrow transaction
func CalculateEscrowFees(escrowAmount uint64, hasDispute bool, hasExpert bool, appealRound int) *EscrowFees {
    fees := &EscrowFees{}

    // Creation fee: 0.5% of escrow amount (min 10 coins)
    fees.CreationFee = max(escrowAmount*5/1000, 10)

    // Network fee: 0.1% of escrow amount
    fees.NetworkFee = max(escrowAmount/1000, 1)

    // Arbiter fees (only if dispute)
    if hasDispute {
        // Base arbiter fee: 1% of escrow amount (min 50, max 500)
        fees.ArbiterBaseFee = min(max(escrowAmount/100, 50), 500)

        // Per-arbiter voting fee: 10 coins per arbiter
        // Standard dispute: 7 arbiters = 70 coins
        fees.ArbiterPerVoteFee = 10 * ArbiterCommitteeSize
    }

    // Expert witness fee (only if expert used)
    if hasExpert {
        // Expert fee: 2% of escrow (min 100, max 1000)
        fees.ExpertWitnessFee = min(max(escrowAmount*2/100, 100), 1000)
    }

    // Appeal fee (only if appealed)
    if appealRound > 0 {
        fees.AppealFee = CalculateAppealFee(nil, appealRound)  // Depends on round
    }

    // Total fees
    fees.TotalFees = fees.CreationFee +
        fees.ArbiterBaseFee +
        fees.ArbiterPerVoteFee +
        fees.ExpertWitnessFee +
        fees.AppealFee +
        fees.NetworkFee

    return fees
}
```

### Fee Payment Responsibility

```go
// FeeAllocation determines who pays which fees
type FeeAllocation struct {
    BuyerPays  uint64
    SellerPays uint64
    Breakdown  map[string]FeePayment
}

type FeePayment struct {
    Amount       uint64
    PaidBy       [32]byte  // NodeID
    Purpose      string
    RefundableIf string    // Condition for refund
}

// AllocateEscrowFees assigns fee responsibility
func AllocateEscrowFees(
    escrow *Escrow,
    fees *EscrowFees,
    resolution *DisputeResolution,
) *FeeAllocation {
    allocation := &FeeAllocation{
        Breakdown: make(map[string]FeePayment),
    }

    // Creation fee: ALWAYS paid by buyer (non-refundable)
    allocation.Breakdown["creation_fee"] = FeePayment{
        Amount:       fees.CreationFee,
        PaidBy:       escrow.Buyer,
        Purpose:      "escrow creation",
        RefundableIf: "never",
    }
    allocation.BuyerPays += fees.CreationFee

    // Network fee: ALWAYS paid by seller (non-refundable)
    allocation.Breakdown["network_fee"] = FeePayment{
        Amount:       fees.NetworkFee,
        PaidBy:       escrow.Seller,
        Purpose:      "network maintenance",
        RefundableIf: "never",
    }
    allocation.SellerPays += fees.NetworkFee

    // Arbiter fees: Paid by LOSING party
    if fees.ArbiterBaseFee > 0 || fees.ArbiterPerVoteFee > 0 {
        arbiterTotal := fees.ArbiterBaseFee + fees.ArbiterPerVoteFee

        switch resolution.Outcome {
        case OutcomeRelease:
            // Seller wins - buyer pays arbiter fees
            allocation.Breakdown["arbiter_fees"] = FeePayment{
                Amount:       arbiterTotal,
                PaidBy:       escrow.Buyer,
                Purpose:      "arbiter compensation",
                RefundableIf: "never",
            }
            allocation.BuyerPays += arbiterTotal

        case OutcomeRefund:
            // Buyer wins - seller pays arbiter fees
            allocation.Breakdown["arbiter_fees"] = FeePayment{
                Amount:       arbiterTotal,
                PaidBy:       escrow.Seller,
                Purpose:      "arbiter compensation",
                RefundableIf: "never",
            }
            allocation.SellerPays += arbiterTotal

        case OutcomeSplit:
            // Split outcome - both parties split arbiter fees
            buyerShare := arbiterTotal / 2
            sellerShare := arbiterTotal - buyerShare

            allocation.Breakdown["arbiter_fees_buyer"] = FeePayment{
                Amount:       buyerShare,
                PaidBy:       escrow.Buyer,
                Purpose:      "arbiter compensation (split)",
                RefundableIf: "never",
            }
            allocation.Breakdown["arbiter_fees_seller"] = FeePayment{
                Amount:       sellerShare,
                PaidBy:       escrow.Seller,
                Purpose:      "arbiter compensation (split)",
                RefundableIf: "never",
            }
            allocation.BuyerPays += buyerShare
            allocation.SellerPays += sellerShare
        }
    }

    // Expert witness fee: Paid by LOSING party
    if fees.ExpertWitnessFee > 0 {
        switch resolution.Outcome {
        case OutcomeRelease:
            allocation.Breakdown["expert_fee"] = FeePayment{
                Amount:       fees.ExpertWitnessFee,
                PaidBy:       escrow.Buyer,
                Purpose:      "expert witness",
                RefundableIf: "never",
            }
            allocation.BuyerPays += fees.ExpertWitnessFee

        case OutcomeRefund:
            allocation.Breakdown["expert_fee"] = FeePayment{
                Amount:       fees.ExpertWitnessFee,
                PaidBy:       escrow.Seller,
                Purpose:      "expert witness",
                RefundableIf: "never",
            }
            allocation.SellerPays += fees.ExpertWitnessFee

        case OutcomeSplit:
            expertBuyerShare := fees.ExpertWitnessFee / 2
            expertSellerShare := fees.ExpertWitnessFee - expertBuyerShare

            allocation.Breakdown["expert_fee_buyer"] = FeePayment{
                Amount:       expertBuyerShare,
                PaidBy:       escrow.Buyer,
                Purpose:      "expert witness (split)",
                RefundableIf: "never",
            }
            allocation.Breakdown["expert_fee_seller"] = FeePayment{
                Amount:       expertSellerShare,
                PaidBy:       escrow.Seller,
                Purpose:      "expert witness (split)",
                RefundableIf: "never",
            }
            allocation.BuyerPays += expertBuyerShare
            allocation.SellerPays += expertSellerShare
        }
    }

    // Appeal fee: Paid by appellant
    // - Refunded if appeal succeeds (upheld or modified)
    // - Kept by system if appeal fails
    if fees.AppealFee > 0 {
        allocation.Breakdown["appeal_fee"] = FeePayment{
            Amount:       fees.AppealFee,
            PaidBy:       resolution.AppellantID,  // Whoever filed appeal
            Purpose:      "appeal processing",
            RefundableIf: "appeal_succeeds",
        }

        if resolution.AppellantID == escrow.Buyer {
            allocation.BuyerPays += fees.AppealFee
        } else {
            allocation.SellerPays += fees.AppealFee
        }
    }

    return allocation
}
```

### Fee Distribution Timing

```go
// FeeDistributionSchedule defines when fees are distributed
type FeeDistributionSchedule struct {
    CreationFee     string  // "immediate"
    NetworkFee      string  // "on_completion"
    ArbiterFees     string  // "after_dispute_resolution"
    ExpertFees      string  // "after_testimony_submission"
    AppealFees      string  // "after_appeal_decision"
}

var DefaultFeeDistribution = FeeDistributionSchedule{
    CreationFee: "immediate",
    NetworkFee:  "on_completion",
    ArbiterFees: "after_dispute_resolution",
    ExpertFees:  "after_testimony_submission",
    AppealFees:  "after_appeal_decision",
}

// DistributeFees handles fee payments at appropriate times
func DistributeFees(escrow *Escrow, fees *EscrowFees, stage string) error {
    switch stage {
    case "immediate":
        // Creation fee: deducted from escrow immediately
        return DeductFee(escrow, fees.CreationFee, "creation_fee")

    case "on_completion":
        // Network fee: deducted when escrow completes successfully
        return DeductFee(escrow, fees.NetworkFee, "network_fee")

    case "after_dispute_resolution":
        // Arbiter fees: paid after dispute is resolved
        return DistributeArbiterFees(escrow, fees.ArbiterBaseFee, fees.ArbiterPerVoteFee)

    case "after_testimony_submission":
        // Expert fees: paid after expert submits testimony
        return PayExpertWitness(escrow, fees.ExpertWitnessFee)

    case "after_appeal_decision":
        // Appeal fees: refunded or kept based on appeal outcome
        return ProcessAppealFee(escrow, fees.AppealFee)

    default:
        return ErrUnknownFeeStage{Stage: stage}
    }
}
```

---

## Dispute Evidence Retention

All dispute evidence must be retained for audit and appeal purposes.

### Evidence Retention Policy

```go
// EvidenceRetentionPolicy defines storage requirements
type EvidenceRetentionPolicy struct {
    RetentionPeriod     time.Duration  // How long to retain evidence
    EncryptionRequired  bool           // Must be encrypted at rest
    RedundancyFactor    int            // Number of redundant copies
    AccessControl       AccessPolicy   // Who can access evidence
    DeletionPolicy      DeletionPolicy // How evidence is deleted
}

var DefaultEvidenceRetention = EvidenceRetentionPolicy{
    RetentionPeriod:    365 * 24 * time.Hour,  // 1 year
    EncryptionRequired: true,
    RedundancyFactor:   3,  // 3 copies across different nodes
    AccessControl:      AccessPolicyRestricted,
    DeletionPolicy:     DeletionPolicySecure,
}
```

### Evidence Storage Structure

```go
// DisputeEvidenceArchive stores all evidence for a dispute
type DisputeEvidenceArchive struct {
    DisputeID         [32]byte
    CreatedAt         time.Time
    ExpiresAt         time.Time
    RetentionPeriod   time.Duration

    // Evidence categories
    BuyerEvidence     []StoredEvidence
    SellerEvidence    []StoredEvidence
    ArbiterNotes      []ArbiterNote
    ExpertTestimony   *ExpertTestimony
    AppealDocuments   []AppealDocument

    // Metadata
    TotalSize         uint64          // Total bytes stored
    EncryptionKey     []byte          // Encryption key (encrypted with network key)
    AccessLog         []AccessRecord  // Who accessed what and when
    IntegrityHash     [32]byte        // SHA256 of all evidence

    // Storage locations
    StorageNodes      [][32]byte      // NodeIDs storing copies
}

// StoredEvidence represents archived evidence
type StoredEvidence struct {
    EvidenceID        [32]byte
    Type              EvidenceType
    SubmittedBy       [32]byte
    SubmittedAt       time.Time
    ContentHash       [32]byte        // SHA256 of content
    EncryptedContent  []byte          // Encrypted evidence data
    Signature         []byte          // TPM signature
    Metadata          map[string]string
}

// AccessRecord logs evidence access
type AccessRecord struct {
    Timestamp         time.Time
    AccessedBy        [32]byte        // NodeID
    EvidenceIDs       [][32]byte      // Which evidence was accessed
    AccessReason      string          // "appeal", "audit", "review"
    AuthorizationProof []byte         // Proof of authorized access
}
```

### Evidence Format Requirements

```go
// EvidenceFormatRequirements defines acceptable formats
type EvidenceFormatRequirements struct {
    AcceptedImageFormats []string      // e.g., ["jpg", "png", "webp"]
    AcceptedVideoFormats []string      // e.g., ["mp4", "webm"]
    AcceptedDocFormats   []string      // e.g., ["pdf", "txt", "md"]
    MaxFileSize          uint64        // Maximum file size in bytes
    RequireMetadata      bool          // Must include metadata
    RequireTimestamp     bool          // Must be timestamped
    RequireSignature     bool          // Must be TPM-signed
}

var DefaultEvidenceFormat = EvidenceFormatRequirements{
    AcceptedImageFormats: []string{"jpg", "jpeg", "png", "webp"},
    AcceptedVideoFormats: []string{"mp4", "webm", "avi"},
    AcceptedDocFormats:   []string{"pdf", "txt", "md", "json"},
    MaxFileSize:          100 * 1024 * 1024,  // 100 MB
    RequireMetadata:      true,
    RequireTimestamp:     true,
    RequireSignature:     true,
}

// ValidateEvidenceFormat checks if evidence meets requirements
func ValidateEvidenceFormat(evidence *StoredEvidence, reqs *EvidenceFormatRequirements) error {
    // Check file size
    if uint64(len(evidence.EncryptedContent)) > reqs.MaxFileSize {
        return ErrEvidenceTooLarge{
            Size:    uint64(len(evidence.EncryptedContent)),
            MaxSize: reqs.MaxFileSize,
        }
    }

    // Check timestamp
    if reqs.RequireTimestamp && evidence.SubmittedAt.IsZero() {
        return ErrMissingTimestamp
    }

    // Check signature
    if reqs.RequireSignature && len(evidence.Signature) == 0 {
        return ErrMissingSignature
    }

    // Verify content hash
    computedHash := sha256.Sum256(evidence.EncryptedContent)
    if computedHash != evidence.ContentHash {
        return ErrContentHashMismatch{
            Expected: evidence.ContentHash,
            Actual:   computedHash,
        }
    }

    return nil
}
```

### Evidence Access Control

```go
// AccessPolicy defines who can access evidence
type AccessPolicy uint8

const (
    // Public: Anyone can view
    AccessPolicyPublic AccessPolicy = 1

    // Restricted: Only dispute parties + arbiters + appeals committee
    AccessPolicyRestricted AccessPolicy = 2

    // Confidential: Only dispute parties
    AccessPolicyConfidential AccessPolicy = 3

    // Sealed: Only arbiters and appeals committee
    AccessPolicySealed AccessPolicy = 4
)

// CheckEvidenceAccess verifies if accessor has permission
func CheckEvidenceAccess(
    archive *DisputeEvidenceArchive,
    accessorID [32]byte,
    reason string,
) error {
    policy := DefaultEvidenceRetention.AccessControl

    switch policy {
    case AccessPolicyPublic:
        // Anyone can access
        return nil

    case AccessPolicyRestricted:
        // Only dispute parties, arbiters, appeal judges
        authorized := isDisputeParty(archive.DisputeID, accessorID) ||
            isArbiter(archive.DisputeID, accessorID) ||
            isAppealJudge(archive.DisputeID, accessorID)

        if !authorized {
            return ErrUnauthorizedEvidenceAccess{
                DisputeID:  archive.DisputeID,
                AccessorID: accessorID,
            }
        }

    case AccessPolicyConfidential:
        // Only dispute parties
        if !isDisputeParty(archive.DisputeID, accessorID) {
            return ErrUnauthorizedEvidenceAccess{
                DisputeID:  archive.DisputeID,
                AccessorID: accessorID,
            }
        }

    case AccessPolicySealed:
        // Only arbiters and appeal judges
        authorized := isArbiter(archive.DisputeID, accessorID) ||
            isAppealJudge(archive.DisputeID, accessorID)

        if !authorized {
            return ErrUnauthorizedEvidenceAccess{
                DisputeID:  archive.DisputeID,
                AccessorID: accessorID,
            }
        }
    }

    // Log access
    LogEvidenceAccess(archive, accessorID, reason)

    return nil
}

// LogEvidenceAccess records who accessed evidence
func LogEvidenceAccess(
    archive *DisputeEvidenceArchive,
    accessorID [32]byte,
    reason string,
) {
    record := AccessRecord{
        Timestamp:    time.Now(),
        AccessedBy:   accessorID,
        AccessReason: reason,
    }

    archive.AccessLog = append(archive.AccessLog, record)

    // Store updated archive
    StoreEvidenceArchive(archive)
}
```

### Evidence Deletion Policy

```go
// DeletionPolicy defines how evidence is deleted
type DeletionPolicy uint8

const (
    // Secure: Cryptographically erase after retention period
    DeletionPolicySecure DeletionPolicy = 1

    // Archive: Move to long-term cold storage
    DeletionPolicyArchive DeletionPolicy = 2

    // Retain: Never delete (for high-value disputes)
    DeletionPolicyRetain DeletionPolicy = 3
)

// ProcessEvidenceExpiry handles expired evidence
func ProcessEvidenceExpiry(archive *DisputeEvidenceArchive) error {
    now := time.Now()

    // Check if retention period expired
    if now.Before(archive.ExpiresAt) {
        return nil  // Not yet expired
    }

    policy := DefaultEvidenceRetention.DeletionPolicy

    switch policy {
    case DeletionPolicySecure:
        // Securely delete evidence
        return SecureDeleteEvidence(archive)

    case DeletionPolicyArchive:
        // Move to cold storage
        return ArchiveEvidence(archive)

    case DeletionPolicyRetain:
        // Extend retention indefinitely
        archive.ExpiresAt = time.Now().Add(100 * 365 * 24 * time.Hour)  // 100 years
        return StoreEvidenceArchive(archive)

    default:
        return ErrUnknownDeletionPolicy{Policy: policy}
    }
}

// SecureDeleteEvidence cryptographically erases evidence
func SecureDeleteEvidence(archive *DisputeEvidenceArchive) error {
    // 1. Verify retention period expired
    if time.Now().Before(archive.ExpiresAt) {
        return ErrPrematureEvidenceDeletion{
            ExpiresAt: archive.ExpiresAt,
            Now:       time.Now(),
        }
    }

    // 2. Create deletion record (for audit)
    deletionRecord := &EvidenceDeletionRecord{
        DisputeID:    archive.DisputeID,
        DeletedAt:    time.Now(),
        DeletedBy:    [32]byte{},  // System
        Reason:       "retention_period_expired",
        EvidenceHash: archive.IntegrityHash,
    }

    // 3. Store deletion record
    if err := StoreDeletionRecord(deletionRecord); err != nil {
        return err
    }

    // 4. Securely overwrite encryption key
    for i := range archive.EncryptionKey {
        archive.EncryptionKey[i] = 0
    }

    // 5. Delete evidence from all storage nodes
    for _, nodeID := range archive.StorageNodes {
        DeleteEvidenceFromNode(nodeID, archive.DisputeID)
    }

    // 6. Remove archive entry
    return DeleteEvidenceArchive(archive.DisputeID)
}

// EvidenceDeletionRecord logs evidence deletion for audit
type EvidenceDeletionRecord struct {
    DisputeID    [32]byte
    DeletedAt    time.Time
    DeletedBy    [32]byte
    Reason       string
    EvidenceHash [32]byte  // Hash of deleted evidence (for verification)
}
```

### Escrow Flow

```
                          ESCROW PAYMENT FLOW

Buyer                     Escrow Service                 Seller
-----                     --------------                 ------

  |                            |                            |
  | 1. Create Escrow           |                            |
  |--------------------------->|                            |
  |    (order details)         |                            |
  |                            |                            |
  | 2. Fund Escrow             |                            |
  |--------------------------->|                            |
  |    (currency transfer)     |                            |
  |                            |                            |
  |                            | 3. Notify Funded           |
  |                            |--------------------------->|
  |                            |                            |
  |                            | 4. Fulfill Order           |
  |<---------------------------|----------------------------|
  |    (goods/services)        |                            |
  |                            |                            |
  | 5. Confirm Receipt         |                            |
  |--------------------------->|                            |
  |    (buyer signature)       |                            |
  |                            |                            |
  |                            | 6. Release Funds           |
  |                            |--------------------------->|
  |                            |    (automatic transfer)    |
  |                            |                            |

                          DISPUTE RESOLUTION

  |                            |                            |
  | X. Initiate Dispute        |                            |
  |--------------------------->|                            |
  |    (reason + evidence)     |                            |
  |                            |                            |
  |                            | Arbiter Assigned           |
  |                            |--------------------------->|
  |                            |                            |
  |                      +-----+-----+                      |
  |                      |  ARBITER  |                      |
  |                      +-----------+                      |
  |                            |                            |
  |   Review Evidence          |    Review Evidence         |
  |<---------------------------|--------------------------->|
  |                            |                            |
  |                     Decision Made                       |
  |<---------------------------|--------------------------->|
  |    (release/refund/split)  |                            |
  |                            |                            |
```

---

## Security Considerations

### Trust Requirements

Only nodes with TrustLevel=Trusted (hardware TPM with whitelisted manufacturer EK) can:

1. **Create service advertisements**
2. **Operate stores**
3. **List products**
4. **Accept orders**
5. **Hold escrow as arbiter**

Untrusted nodes can:
- Browse and search services
- Place orders (as buyers)
- Leave reviews (with verification)

### Signature Verification

All service advertisements must be cryptographically signed:

```go
// VerifyAdvertisementSignature validates the cryptographic signature
func VerifyAdvertisementSignature(ad *ServiceAdvertisement) error {
    // Extract public key from IDevID certificate
    cert, err := x509.ParseCertificate(ad.Certificate)
    if err != nil {
        return ErrInvalidCertificate{Reason: err.Error()}
    }

    // Verify certificate was FROST-signed by CA pool
    if err := verifyCACertificate(cert); err != nil {
        return ErrCertificateNotTrusted{Reason: err.Error()}
    }

    // Compute signing payload (everything except signature)
    payload := computeSigningPayload(ad)

    // Verify Ed25519 signature
    pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
    if !ok {
        return ErrUnsupportedKeyType{}
    }

    if !ed25519.Verify(pubKey, payload, ad.Signature) {
        return ErrSignatureVerificationFailed{}
    }

    return nil
}

// computeSigningPayload creates deterministic payload for signing
func computeSigningPayload(ad *ServiceAdvertisement) []byte {
    h := sha256.New()
    h.Write(ad.NodeID[:])
    h.Write([]byte(ad.ServiceType))
    h.Write([]byte(ad.Name))
    h.Write([]byte(ad.Description))
    for _, tag := range ad.Tags {
        h.Write([]byte(tag))
    }
    binary.Write(h, binary.BigEndian, ad.Pricing.BasePrice)
    binary.Write(h, binary.BigEndian, ad.PublishedAt)
    binary.Write(h, binary.BigEndian, ad.ExpiresAt)
    return h.Sum(nil)
}
```

### Anti-Fraud Measures

| Threat | Mitigation |
|--------|------------|
| Fake listings | TPM-backed identity, reputation history |
| Price manipulation | Historical price tracking, anomaly detection |
| Sybil attacks | TPM attestation, minimum reputation for advertising |
| Escrow fraud | Multi-signature release, arbiter system |
| Review bombing | Verified purchase requirement, reputation-weighted reviews |
| Inventory fraud | On-chain inventory commitments, refund penalties |

### Rate Limiting

```go
// AdvertisementRateLimiter prevents spam and abuse
type AdvertisementRateLimiter struct {
    maxAdsPerNode        int           // Max active advertisements per node
    maxUpdatesPerHour    int           // Max updates per hour per node
    minUpdateInterval    time.Duration // Minimum time between updates
    cooldownOnViolation  time.Duration // Cooldown after rate limit exceeded
}

var DefaultRateLimits = AdvertisementRateLimiter{
    maxAdsPerNode:       100,
    maxUpdatesPerHour:   20,
    minUpdateInterval:   5 * time.Minute,
    cooldownOnViolation: 1 * time.Hour,
}
```

---

## API Endpoints

### REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/services` | Create service advertisement |
| GET | `/api/v1/services/{id}` | Get service by ID |
| PUT | `/api/v1/services/{id}` | Update service advertisement |
| DELETE | `/api/v1/services/{id}` | Remove service advertisement |
| GET | `/api/v1/services/search` | Search services |
| GET | `/api/v1/services/browse/{type}` | Browse by type |
| GET | `/api/v1/providers/{nodeId}/services` | Get provider's services |
| POST | `/api/v1/stores` | Create store |
| GET | `/api/v1/stores/{id}` | Get store |
| POST | `/api/v1/stores/{id}/products` | Create product |
| GET | `/api/v1/products/{id}` | Get product |
| GET | `/api/v1/products/search` | Search products |
| POST | `/api/v1/orders` | Create order |
| GET | `/api/v1/orders/{id}` | Get order |
| PUT | `/api/v1/orders/{id}/status` | Update order status |
| POST | `/api/v1/escrows` | Create escrow |
| POST | `/api/v1/escrows/{id}/fund` | Fund escrow |
| POST | `/api/v1/escrows/{id}/release` | Release escrow |
| POST | `/api/v1/escrows/{id}/dispute` | Dispute escrow |

### gRPC Service

```protobuf
service DiscoveryService {
    // Service advertisements
    rpc Advertise(AdvertiseRequest) returns (AdvertiseResponse);
    rpc Search(SearchRequest) returns (SearchResponse);
    rpc Browse(BrowseRequest) returns (stream ServiceAdvertisement);
    rpc GetService(GetServiceRequest) returns (ServiceAdvertisement);
    rpc RemoveAdvertisement(RemoveRequest) returns (RemoveResponse);
    rpc Subscribe(SubscribeRequest) returns (stream ServiceAdvertisement);

    // E-commerce
    rpc CreateStore(CreateStoreRequest) returns (Store);
    rpc CreateProduct(CreateProductRequest) returns (Product);
    rpc SearchProducts(ProductSearchRequest) returns (ProductSearchResponse);
    rpc CreateOrder(CreateOrderRequest) returns (Order);
    rpc GetOrder(GetOrderRequest) returns (Order);
    rpc UpdateOrderStatus(UpdateStatusRequest) returns (Order);

    // Escrow
    rpc CreateEscrow(CreateEscrowRequest) returns (Escrow);
    rpc FundEscrow(FundEscrowRequest) returns (Escrow);
    rpc ReleaseEscrow(ReleaseEscrowRequest) returns (Escrow);
    rpc DisputeEscrow(DisputeRequest) returns (Escrow);
    rpc ResolveDispute(ResolveRequest) returns (Escrow);
}
```

### QUIC Endpoints

QUIC endpoints mirror the gRPC service with the same request/response patterns for low-latency, mobile-friendly access.

### MCP Tools

```json
{
  "tools": [
    {
      "name": "discover_services",
      "description": "Search for services in the DHT marketplace",
      "parameters": {
        "keywords": "string[]",
        "service_types": "string[]",
        "min_reputation": "number",
        "max_price": "number"
      }
    },
    {
      "name": "get_service_details",
      "description": "Get detailed information about a service",
      "parameters": {
        "service_id": "string"
      }
    },
    {
      "name": "browse_products",
      "description": "Browse products from e-commerce stores",
      "parameters": {
        "category": "string",
        "store_id": "string",
        "price_range": "object"
      }
    },
    {
      "name": "check_order_status",
      "description": "Check the status of an order",
      "parameters": {
        "order_id": "string"
      }
    },
    {
      "name": "get_escrow_status",
      "description": "Get the status of a payment escrow",
      "parameters": {
        "escrow_id": "string"
      }
    }
  ]
}
```

### Unix Socket API

The Unix socket API at `/run/platformd.sock` provides local IPC access with the same functionality as REST endpoints, optimized for CLI tools and local integrations.

---

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Search latency | <100ms (indexed queries) |
| DHT lookup latency | ~150ms per hop |
| Advertisement size | ~2-5 KB |
| Index update frequency | Real-time for prices, 10 blocks for capacity |
| Maximum results per query | 1000 |
| Advertisement expiry | Configurable (default: 30 days) |
| Escrow creation time | ~500ms |
| Order processing | ~1-2 seconds |

---

## Error Types

```go
var (
    ErrUntrustedNodeCannotAdvertise = errors.New("only trusted nodes can advertise services")
    ErrInvalidCertificate           = errors.New("invalid or expired certificate")
    ErrInvalidSignature             = errors.New("signature verification failed")
    ErrServiceNotFound              = errors.New("service advertisement not found")
    ErrStoreNotFound                = errors.New("store not found")
    ErrProductNotFound              = errors.New("product not found")
    ErrOrderNotFound                = errors.New("order not found")
    ErrEscrowNotFound               = errors.New("escrow not found")
    ErrInsufficientCapacity         = errors.New("insufficient capacity")
    ErrInvalidPrice                 = errors.New("invalid price")
    ErrNameTooLong                  = errors.New("name exceeds maximum length")
    ErrDescriptionTooLong           = errors.New("description exceeds maximum length")
    ErrTooManyTags                  = errors.New("too many tags")
    ErrInvalidExpiration            = errors.New("invalid expiration date")
    ErrRateLimitExceeded            = errors.New("rate limit exceeded")
    ErrEscrowAlreadyFunded          = errors.New("escrow already funded")
    ErrEscrowNotFunded              = errors.New("escrow not yet funded")
    ErrUnauthorizedRelease          = errors.New("unauthorized escrow release")
    ErrDisputeInProgress            = errors.New("dispute already in progress")
    ErrOwnershipVerificationFailed  = errors.New("ownership verification failed")
)
```

---

## Related Documents

- [03-security-trust.md](03-security-trust.md) - Trust policies and TPM requirements
- [07-currency-transactions.md](07-currency-transactions.md) - Currency and transaction system
- [09-defense-reputation.md](09-defense-reputation.md) - Reputation system
- [10-governance-economics.md](10-governance-economics.md) - Economic model and service discovery schema

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-08 | Initial specification |
| 1.1 | 2026-01-10 | Added FINAL DESIGN elements: Escrow edge cases (delivery proof validation, buyer offline late disputes, low arbiter pool handling, high-value dispute requirements), Arbiter replacement protocol (refusal, offline, mid-dispute replacement), Client eligibility lifecycle (requirement drop, exemption expiry, provider requirement updates), Exemption management (revocation, audit trail, concurrent limits) |
| 1.2 | 2026-01-10 | Added comprehensive dispute resolution specifications: Service Completion Criteria (objective/subjective delivery metrics, verification protocols, decision authority), Partial Delivery Handling (thresholds, classification, refund formulas), Quality Dispute Procedures (quality metrics framework, evidence requirements, arbiter qualifications), Expert Witness Procedures (eligibility, selection protocol, testimony format, compensation), Appeal Process (eligibility, committee composition, decision process, maximum rounds), Escrow Fee Structure (breakdown, payment responsibility, distribution timing), Dispute Evidence Retention (retention policy, storage structure, access control, deletion policy) |

---

**Version:** 1.2
**Last Updated:** 2026-01-10
**Status:** Complete with Comprehensive Dispute Resolution Specifications
