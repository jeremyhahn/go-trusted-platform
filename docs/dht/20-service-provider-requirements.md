# Service Provider Trust and Reputation Requirements

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.

This document specifies the comprehensive trust and reputation requirement system for service providers in the go-trusted-platform DHT. This system enables service providers to configure minimum eligibility criteria that potential clients must meet before accessing their services.

---

## Overview

Service providers offering services through the DHT service discovery marketplace can configure trust and reputation requirements that clients must satisfy. This capability allows providers to:

1. **Protect against untrusted clients**: Require minimum trust levels (Trusted vs. Untrusted)
2. **Filter by reputation**: Set minimum reputation thresholds (0.0-1.0)
3. **Apply custom criteria**: Geographic restrictions, network age, service-specific requirements
4. **Enforce automatically**: Requirements checked at contract negotiation and service access

The system applies uniformly across all ServiceContract types: Agent, Compute, Storage, E-Commerce, and Network services.

### Design Principles

1. **Provider Autonomy**: Providers set their own eligibility criteria
2. **Clear Communication**: Clients see requirements before attempting to engage
3. **Automatic Enforcement**: Requirements validated at multiple checkpoints
4. **Graduated Access**: Different service tiers can have different requirements
5. **Economic Incentives**: Higher requirements allow premium pricing

---

## ServiceRequirements Structure

The `ServiceRequirements` structure defines eligibility criteria that clients must meet to access a service.

### Core Structure

```go
// ServiceRequirements defines eligibility criteria for service clients
type ServiceRequirements struct {
	// Trust Requirements
	MinTrustLevel     TrustLevel       // Minimum trust level (Trusted or Untrusted)
	RequireHardwareTPM bool            // Require hardware TPM attestation

	// Reputation Requirements
	MinReputation     float64          // Minimum reputation score (0.0-1.0)
	MaxViolations     uint32           // Maximum violation count allowed
	MinNetworkAge     time.Duration    // Minimum time on network

	// Geographic Requirements
	AllowedRegions    []string         // Allowed geographic regions (empty = all)
	BlockedRegions    []string         // Blocked geographic regions

	// Service-Specific Requirements
	CustomRequirements map[string]interface{} // Type-specific requirements

	// Verification Settings
	VerificationMode  VerificationMode // How to verify requirements
	EnforcementLevel  EnforcementLevel // Strict or advisory

	// Exemptions
	ExemptionList     [][32]byte       // Node IDs exempt from requirements
	WhitelistEnabled  bool             // Whether exemption list is active
}

// TrustLevel represents node trust classification
type TrustLevel uint8

const (
	TrustLevelUntrusted TrustLevel = 0 // Software TPM or unverified EK
	TrustLevelTrusted   TrustLevel = 1 // Hardware TPM with whitelisted EK
)

// VerificationMode defines when requirements are checked
type VerificationMode uint8

const (
	// VerifyAtAdvertisement - Check when service is advertised in search
	VerifyAtAdvertisement VerificationMode = 1 << 0

	// VerifyAtContract - Check during contract negotiation
	VerifyAtContract VerificationMode = 1 << 1

	// VerifyAtAccess - Check at service access time
	VerifyAtAccess VerificationMode = 1 << 2

	// VerifyPeriodic - Recheck periodically during service delivery
	VerifyPeriodic VerificationMode = 1 << 3

	// VerifyAll - All verification modes enabled
	VerifyAll = VerifyAtAdvertisement | VerifyAtContract | VerifyAtAccess | VerifyPeriodic
)

// EnforcementLevel defines how violations are handled
type EnforcementLevel uint8

const (
	// EnforcementAdvisory - Show warnings but allow access
	EnforcementAdvisory EnforcementLevel = 0

	// EnforcementStrict - Block access if requirements not met
	EnforcementStrict EnforcementLevel = 1

	// EnforcementGracePeriod - Allow temporary access with grace period
	EnforcementGracePeriod EnforcementLevel = 2
)
```

### Preset Requirement Templates

Common requirement configurations for different service security levels:

```go
// PresetRequirements provides standard requirement templates
var PresetRequirements = struct {
	OpenAccess      ServiceRequirements
	BasicTrust      ServiceRequirements
	StandardTrust   ServiceRequirements
	HighTrust       ServiceRequirements
	MaximumSecurity ServiceRequirements
}{
	// OpenAccess - No restrictions (accept all clients)
	OpenAccess: ServiceRequirements{
		MinTrustLevel:     TrustLevelUntrusted,
		RequireHardwareTPM: false,
		MinReputation:     0.0,
		MaxViolations:     ^uint32(0), // Unlimited
		MinNetworkAge:     0,
		VerificationMode:  VerifyAtContract,
		EnforcementLevel:  EnforcementAdvisory,
	},

	// BasicTrust - Accept untrusted nodes with minimum reputation
	BasicTrust: ServiceRequirements{
		MinTrustLevel:     TrustLevelUntrusted,
		RequireHardwareTPM: false,
		MinReputation:     0.50, // 50% reputation minimum
		MaxViolations:     10,
		MinNetworkAge:     7 * 24 * time.Hour, // 7 days
		VerificationMode:  VerifyAtContract | VerifyAtAccess,
		EnforcementLevel:  EnforcementStrict,
	},

	// StandardTrust - Require trusted nodes with moderate reputation
	StandardTrust: ServiceRequirements{
		MinTrustLevel:     TrustLevelTrusted,
		RequireHardwareTPM: true,
		MinReputation:     0.70, // Standard trust level
		MaxViolations:     5,
		MinNetworkAge:     30 * 24 * time.Hour, // 30 days
		VerificationMode:  VerifyAtContract | VerifyAtAccess | VerifyPeriodic,
		EnforcementLevel:  EnforcementStrict,
	},

	// HighTrust - High reputation trusted nodes only
	HighTrust: ServiceRequirements{
		MinTrustLevel:     TrustLevelTrusted,
		RequireHardwareTPM: true,
		MinReputation:     0.80, // Hub level
		MaxViolations:     2,
		MinNetworkAge:     90 * 24 * time.Hour, // 90 days
		VerificationMode:  VerifyAll,
		EnforcementLevel:  EnforcementStrict,
	},

	// MaximumSecurity - Coordinator-level nodes only
	MaximumSecurity: ServiceRequirements{
		MinTrustLevel:     TrustLevelTrusted,
		RequireHardwareTPM: true,
		MinReputation:     0.95, // Coordinator level
		MaxViolations:     0,
		MinNetworkAge:     180 * 24 * time.Hour, // 180 days
		VerificationMode:  VerifyAll,
		EnforcementLevel:  EnforcementStrict,
	},
}
```

---

## Service-Specific Requirements

Different service types have specialized requirement extensions:

### Agent Service Requirements

```go
// AgentClientRequirements extends ServiceRequirements for AI agent services
type AgentClientRequirements struct {
	ServiceRequirements

	// Agent-Specific
	MinTokenBudget    uint64           // Minimum token budget required
	RequireDataAccess bool             // Require data access permissions
	AllowedTaskTypes  []TaskType       // Permitted task types for client
	MaxConcurrency    uint32           // Maximum concurrent sessions
}
```

### Compute Service Requirements

```go
// ComputeClientRequirements extends ServiceRequirements for compute services
type ComputeClientRequirements struct {
	ServiceRequirements

	// Compute-Specific
	RequirePaymentBond bool             // Require upfront payment bond
	MinCPUCores       uint32           // Minimum reserved capacity
	BannedImages      []string         // Blocked OS images
	RequireSSHKey     bool             // Require SSH key registration
}
```

### Storage Service Requirements

```go
// StorageClientRequirements extends ServiceRequirements for storage services
type StorageClientRequirements struct {
	ServiceRequirements

	// Storage-Specific
	MinStorageQuota   uint64           // Minimum purchase commitment (GB)
	BannedFileTypes   []string         // Prohibited file extensions
	RequireEncryption bool             // Require client-side encryption
	MaxFileSize       uint64           // Maximum individual file size
}
```

### E-Commerce Service Requirements

```go
// ECommerceClientRequirements extends ServiceRequirements for e-commerce
type ECommerceClientRequirements struct {
	ServiceRequirements

	// E-Commerce-Specific
	MinOrderValue     uint64           // Minimum order value
	RequireVerifiedID bool             // Require identity verification
	ShippingRestrictions []string      // Blocked shipping countries
	PaymentMethods    []PaymentMethod  // Accepted payment methods
	MaxOrdersPerDay   uint32           // Rate limit on orders
}
```

### Network Service Requirements

```go
// NetworkClientRequirements extends ServiceRequirements for network services
type NetworkClientRequirements struct {
	ServiceRequirements

	// Network-Specific
	MinBandwidth      uint32           // Minimum bandwidth commitment (Mbps)
	BannedPorts       []uint16         // Prohibited ports
	RequireDDoSBond   bool             // Require DDoS protection bond
	MaxConnections    uint32           // Connection limit
	TrafficLimits     TrafficPolicy    // Traffic policy restrictions
}

// TrafficPolicy defines traffic restrictions
type TrafficPolicy struct {
	BlockTor          bool
	BlockVPN          bool
	BlockProxies      bool
	AllowP2P          bool
	MaxPacketRate     uint64
}
```

---

## RequirementVerification Interface

The `RequirementVerification` interface handles checking client eligibility:

```go
// RequirementVerifier validates client eligibility against service requirements
type RequirementVerifier interface {
	// VerifyEligibility checks if a client meets service requirements
	VerifyEligibility(ctx context.Context, clientID [32]byte, requirements *ServiceRequirements) (*VerificationResult, error)

	// VerifyTrustLevel validates client's trust level
	VerifyTrustLevel(ctx context.Context, clientID [32]byte, minLevel TrustLevel) error

	// VerifyReputation validates client's reputation score
	VerifyReputation(ctx context.Context, clientID [32]byte, minScore float64) error

	// VerifyNetworkAge validates client's time on network
	VerifyNetworkAge(ctx context.Context, clientID [32]byte, minAge time.Duration) error

	// VerifyGeography validates client's geographic location
	VerifyGeography(ctx context.Context, clientID [32]byte, allowed, blocked []string) error

	// VerifyCustom validates service-specific requirements
	VerifyCustom(ctx context.Context, clientID [32]byte, custom map[string]interface{}) error

	// ContinuousVerification performs periodic rechecks during service delivery
	ContinuousVerification(ctx context.Context, contractID [32]byte, interval time.Duration) (<-chan *VerificationResult, error)
}

// VerificationResult contains the outcome of eligibility verification
type VerificationResult struct {
	ClientID          [32]byte
	ServiceID         [32]byte
	Eligible          bool
	Requirements      *ServiceRequirements

	// Detailed Results
	TrustCheck        CheckResult
	ReputationCheck   CheckResult
	NetworkAgeCheck   CheckResult
	GeographyCheck    CheckResult
	CustomChecks      map[string]CheckResult

	// Metadata
	VerifiedAt        time.Time
	VerificationMode  VerificationMode
	NextCheckDue      *time.Time // For periodic verification

	// Failure Information
	FailureReasons    []string
	RecommendedAction string
}

// CheckResult represents the outcome of an individual requirement check
type CheckResult struct {
	Passed        bool
	Actual        interface{} // Actual value (e.g., reputation score)
	Required      interface{} // Required value
	Message       string
	Severity      Severity
}

// Severity indicates the importance of a failed check
type Severity uint8

const (
	SeverityInfo    Severity = 0 // Informational only
	SeverityWarning Severity = 1 // Warning but not blocking
	SeverityError   Severity = 2 // Blocking error
	SeverityCritical Severity = 3 // Critical security violation
)
```

### Default Implementation

```go
// DefaultRequirementVerifier implements RequirementVerifier
type DefaultRequirementVerifier struct {
	dht        DHT
	reputation ReputationService
	trust      TrustVerifier
	registry   NodeRegistry
}

func NewRequirementVerifier(dht DHT, rep ReputationService, trust TrustVerifier, registry NodeRegistry) RequirementVerifier {
	return &DefaultRequirementVerifier{
		dht:        dht,
		reputation: rep,
		trust:      trust,
		registry:   registry,
	}
}

// VerifyEligibility performs comprehensive eligibility verification
func (v *DefaultRequirementVerifier) VerifyEligibility(ctx context.Context, clientID [32]byte, requirements *ServiceRequirements) (*VerificationResult, error) {
	result := &VerificationResult{
		ClientID:     clientID,
		Requirements: requirements,
		CustomChecks: make(map[string]CheckResult),
		VerifiedAt:   time.Now(),
	}

	// Get client node information
	node, err := v.registry.GetNode(ctx, clientID)
	if err != nil {
		return nil, ErrClientNodeNotFound{ClientID: clientID}
	}

	// Check trust level
	result.TrustCheck = v.checkTrustLevel(node, requirements.MinTrustLevel, requirements.RequireHardwareTPM)

	// Check reputation
	result.ReputationCheck = v.checkReputation(ctx, node, requirements.MinReputation, requirements.MaxViolations)

	// Check network age
	result.NetworkAgeCheck = v.checkNetworkAge(node, requirements.MinNetworkAge)

	// Check geography
	result.GeographyCheck = v.checkGeography(node, requirements.AllowedRegions, requirements.BlockedRegions)

	// Check custom requirements
	for key, value := range requirements.CustomRequirements {
		result.CustomChecks[key] = v.verifyCustomRequirement(ctx, node, key, value)
	}

	// Check exemption list
	if requirements.WhitelistEnabled && v.isExempt(clientID, requirements.ExemptionList) {
		result.Eligible = true
		result.RecommendedAction = "Client is on exemption list - all checks bypassed"
		return result, nil
	}

	// Determine overall eligibility
	result.Eligible = result.TrustCheck.Passed &&
		result.ReputationCheck.Passed &&
		result.NetworkAgeCheck.Passed &&
		result.GeographyCheck.Passed &&
		v.allCustomChecksPassed(result.CustomChecks)

	// Populate failure reasons
	if !result.Eligible {
		result.FailureReasons = v.collectFailureReasons(result)
		result.RecommendedAction = v.generateRecommendation(result, requirements)
	}

	// Schedule next periodic check if enabled
	if requirements.VerificationMode&VerifyPeriodic != 0 {
		nextCheck := time.Now().Add(DefaultPeriodicCheckInterval)
		result.NextCheckDue = &nextCheck
	}

	return result, nil
}

func (v *DefaultRequirementVerifier) checkTrustLevel(node *Node, minLevel TrustLevel, requireHardware bool) CheckResult {
	if node.TrustLevel < minLevel {
		return CheckResult{
			Passed:   false,
			Actual:   node.TrustLevel,
			Required: minLevel,
			Message:  fmt.Sprintf("Client trust level %d does not meet minimum %d", node.TrustLevel, minLevel),
			Severity: SeverityError,
		}
	}

	if requireHardware && !node.HasHardwareTPM {
		return CheckResult{
			Passed:   false,
			Actual:   "software TPM",
			Required: "hardware TPM",
			Message:  "Client does not have hardware TPM attestation",
			Severity: SeverityError,
		}
	}

	return CheckResult{
		Passed:   true,
		Actual:   node.TrustLevel,
		Required: minLevel,
		Message:  "Trust level requirement satisfied",
		Severity: SeverityInfo,
	}
}

func (v *DefaultRequirementVerifier) checkReputation(ctx context.Context, node *Node, minRep float64, maxViolations uint32) CheckResult {
	rep, err := v.reputation.GetReputation(ctx, node.NodeID)
	if err != nil {
		return CheckResult{
			Passed:   false,
			Message:  fmt.Sprintf("Failed to retrieve reputation: %v", err),
			Severity: SeverityCritical,
		}
	}

	violations := node.ViolationCount

	if rep < minRep {
		return CheckResult{
			Passed:   false,
			Actual:   rep,
			Required: minRep,
			Message:  fmt.Sprintf("Client reputation %.2f below minimum %.2f", rep, minRep),
			Severity: SeverityError,
		}
	}

	if violations > maxViolations {
		return CheckResult{
			Passed:   false,
			Actual:   violations,
			Required: maxViolations,
			Message:  fmt.Sprintf("Client has %d violations, exceeds maximum %d", violations, maxViolations),
			Severity: SeverityError,
		}
	}

	return CheckResult{
		Passed:   true,
		Actual:   rep,
		Required: minRep,
		Message:  fmt.Sprintf("Reputation %.2f meets minimum %.2f", rep, minRep),
		Severity: SeverityInfo,
	}
}

func (v *DefaultRequirementVerifier) checkNetworkAge(node *Node, minAge time.Duration) CheckResult {
	age := time.Since(node.JoinedAt)

	if age < minAge {
		return CheckResult{
			Passed:   false,
			Actual:   age,
			Required: minAge,
			Message:  fmt.Sprintf("Client network age %s below minimum %s", age, minAge),
			Severity: SeverityError,
		}
	}

	return CheckResult{
		Passed:   true,
		Actual:   age,
		Required: minAge,
		Message:  fmt.Sprintf("Network age %s meets minimum %s", age, minAge),
		Severity: SeverityInfo,
	}
}

func (v *DefaultRequirementVerifier) checkGeography(node *Node, allowed, blocked []string) CheckResult {
	region := node.Region

	// Check blocked list first
	if len(blocked) > 0 && contains(blocked, region) {
		return CheckResult{
			Passed:   false,
			Actual:   region,
			Required: fmt.Sprintf("not in %v", blocked),
			Message:  fmt.Sprintf("Client region %s is blocked", region),
			Severity: SeverityError,
		}
	}

	// Check allowed list (empty allowed list = all regions allowed)
	if len(allowed) > 0 && !contains(allowed, region) {
		return CheckResult{
			Passed:   false,
			Actual:   region,
			Required: fmt.Sprintf("one of %v", allowed),
			Message:  fmt.Sprintf("Client region %s not in allowed list", region),
			Severity: SeverityError,
		}
	}

	return CheckResult{
		Passed:   true,
		Actual:   region,
		Message:  fmt.Sprintf("Region %s is permitted", region),
		Severity: SeverityInfo,
	}
}

func (v *DefaultRequirementVerifier) isExempt(clientID [32]byte, exemptionList [][32]byte) bool {
	for _, exemptID := range exemptionList {
		if exemptID == clientID {
			return true
		}
	}
	return false
}
```

---

## Error Types

Structured error types for requirement verification failures:

```go
// Requirement verification errors
var (
	ErrClientNodeNotFound = errors.New("client node not found in registry")
	ErrTrustLevelTooLow   = errors.New("client trust level does not meet requirements")
	ErrReputationTooLow   = errors.New("client reputation below minimum threshold")
	ErrTooManyViolations  = errors.New("client violation count exceeds maximum")
	ErrNetworkAgeTooLow   = errors.New("client network age below minimum")
	ErrRegionBlocked      = errors.New("client region is blocked")
	ErrRegionNotAllowed   = errors.New("client region not in allowed list")
	ErrCustomCheckFailed  = errors.New("custom requirement check failed")
)

// ErrRequirementsNotMet is the top-level error returned to clients
type ErrRequirementsNotMet struct {
	ClientID       [32]byte
	ServiceID      [32]byte
	Requirements   *ServiceRequirements
	FailureReasons []string
	Recommendation string
}

func (e ErrRequirementsNotMet) Error() string {
	return fmt.Sprintf("client %x does not meet service requirements for %x: %s",
		e.ClientID[:8], e.ServiceID[:8], strings.Join(e.FailureReasons, "; "))
}

// Typed errors with context
type ErrTrustLevelInsufficient struct {
	ClientID     [32]byte
	ActualLevel  TrustLevel
	RequiredLevel TrustLevel
}

func (e ErrTrustLevelInsufficient) Error() string {
	return fmt.Sprintf("client %x trust level %d below required %d",
		e.ClientID[:8], e.ActualLevel, e.RequiredLevel)
}

type ErrReputationInsufficient struct {
	ClientID        [32]byte
	ActualReputation float64
	RequiredReputation float64
}

func (e ErrReputationInsufficient) Error() string {
	return fmt.Sprintf("client %x reputation %.2f below required %.2f",
		e.ClientID[:8], e.ActualReputation, e.RequiredReputation)
}

type ErrGeographicRestriction struct {
	ClientID      [32]byte
	ClientRegion  string
	AllowedRegions []string
	BlockedRegions []string
}

func (e ErrGeographicRestriction) Error() string {
	if len(e.BlockedRegions) > 0 && contains(e.BlockedRegions, e.ClientRegion) {
		return fmt.Sprintf("client %x region %s is blocked",
			e.ClientID[:8], e.ClientRegion)
	}
	return fmt.Sprintf("client %x region %s not in allowed list %v",
		e.ClientID[:8], e.ClientRegion, e.AllowedRegions)
}
```

---

## Integration with ServiceAdvertisement

Service advertisements include requirements so clients can filter before attempting to engage:

```go
// ServiceAdvertisement extended with requirements
type ServiceAdvertisement struct {
	// ... existing fields ...

	// Client Requirements
	ClientRequirements *ServiceRequirements // Eligibility criteria for clients
	RequirementsHash   [32]byte             // Hash of requirements (for integrity)

	// Requirement Display
	RequirementsSummary string              // Human-readable summary
	RequirementsStrict  bool                // Whether enforcement is strict
}

// ValidateAdvertisementRequirements ensures requirements are valid
func ValidateAdvertisementRequirements(ad *ServiceAdvertisement) error {
	if ad.ClientRequirements == nil {
		// No requirements = open access
		return nil
	}

	req := ad.ClientRequirements

	// Validate reputation range
	if req.MinReputation < 0.0 || req.MinReputation > 1.0 {
		return ErrInvalidReputationRange{Value: req.MinReputation}
	}

	// Validate trust level
	if req.MinTrustLevel > TrustLevelTrusted {
		return ErrInvalidTrustLevel{Value: req.MinTrustLevel}
	}

	// Validate network age
	if req.MinNetworkAge < 0 {
		return ErrInvalidNetworkAge{Value: req.MinNetworkAge}
	}

	// Validate regions don't overlap
	if hasOverlap(req.AllowedRegions, req.BlockedRegions) {
		return ErrConflictingRegionRules{
			Allowed: req.AllowedRegions,
			Blocked: req.BlockedRegions,
		}
	}

	// Compute requirements hash for integrity
	ad.RequirementsHash = computeRequirementsHash(req)

	// Generate human-readable summary
	ad.RequirementsSummary = generateRequirementsSummary(req)
	ad.RequirementsStrict = (req.EnforcementLevel == EnforcementStrict)

	return nil
}

// generateRequirementsSummary creates human-readable text
func generateRequirementsSummary(req *ServiceRequirements) string {
	parts := []string{}

	if req.MinTrustLevel == TrustLevelTrusted {
		parts = append(parts, "Trusted nodes only")
	}

	if req.MinReputation > 0 {
		parts = append(parts, fmt.Sprintf("Min reputation: %.2f", req.MinReputation))
	}

	if req.MinNetworkAge > 0 {
		days := int(req.MinNetworkAge.Hours() / 24)
		parts = append(parts, fmt.Sprintf("Min network age: %d days", days))
	}

	if len(req.AllowedRegions) > 0 {
		parts = append(parts, fmt.Sprintf("Regions: %s", strings.Join(req.AllowedRegions, ", ")))
	}

	if len(req.BlockedRegions) > 0 {
		parts = append(parts, fmt.Sprintf("Blocked: %s", strings.Join(req.BlockedRegions, ", ")))
	}

	if len(parts) == 0 {
		return "Open access - no restrictions"
	}

	return strings.Join(parts, " | ")
}
```

---

## Integration with ServiceContract

Service contracts enforce requirements at negotiation and during service delivery:

```go
// ServiceContract extended with requirement enforcement
type ServiceContract struct {
	// ... existing fields ...

	// Requirement Enforcement
	ClientRequirements  *ServiceRequirements    // Requirements client must meet
	InitialVerification *VerificationResult     // Verification at contract creation
	LastVerification    *VerificationResult     // Most recent verification
	VerificationHistory []*VerificationResult   // Historical verifications

	// Enforcement State
	RequirementsMet     bool                    // Current compliance status
	GracePeriodEnd      *time.Time              // Grace period deadline (if applicable)
	ViolationCount      uint32                  // Number of requirement violations
}

// VerifyClientRequirements checks client eligibility during contract negotiation
func VerifyClientRequirements(contract *ServiceContract, verifier RequirementVerifier) error {
	if contract.ClientRequirements == nil {
		// No requirements specified - allow all clients
		contract.RequirementsMet = true
		return nil
	}

	ctx := context.Background()
	result, err := verifier.VerifyEligibility(ctx, contract.Consumer.NodeID, contract.ClientRequirements)
	if err != nil {
		return ErrVerificationFailed{Cause: err}
	}

	contract.InitialVerification = result
	contract.LastVerification = result
	contract.RequirementsMet = result.Eligible

	if !result.Eligible {
		// Handle based on enforcement level
		switch contract.ClientRequirements.EnforcementLevel {
		case EnforcementStrict:
			return ErrRequirementsNotMet{
				ClientID:       contract.Consumer.NodeID,
				ServiceID:      contract.Provider.NodeID,
				Requirements:   contract.ClientRequirements,
				FailureReasons: result.FailureReasons,
				Recommendation: result.RecommendedAction,
			}

		case EnforcementGracePeriod:
			// Allow temporary access with grace period
			gracePeriod := 7 * 24 * time.Hour // 7 days default
			graceEnd := time.Now().Add(gracePeriod)
			contract.GracePeriodEnd = &graceEnd
			contract.RequirementsMet = true // Temporarily allow

			return nil

		case EnforcementAdvisory:
			// Log warning but allow access
			logRequirementWarning(contract, result)
			contract.RequirementsMet = true
			return nil
		}
	}

	return nil
}

// ContinuousRequirementMonitoring performs periodic rechecks
func ContinuousRequirementMonitoring(contract *ServiceContract, verifier RequirementVerifier) error {
	if contract.ClientRequirements == nil {
		return nil
	}

	if contract.ClientRequirements.VerificationMode&VerifyPeriodic == 0 {
		return nil // Periodic verification not enabled
	}

	interval := DefaultPeriodicCheckInterval // 24 hours
	ctx := context.Background()

	checkChan, err := verifier.ContinuousVerification(ctx, contract.ContractID, interval)
	if err != nil {
		return err
	}

	// Monitor verification results
	go func() {
		for result := range checkChan {
			handlePeriodicVerification(contract, result)
		}
	}()

	return nil
}

func handlePeriodicVerification(contract *ServiceContract, result *VerificationResult) {
	contract.LastVerification = result
	contract.VerificationHistory = append(contract.VerificationHistory, result)

	if !result.Eligible {
		contract.ViolationCount++

		// Check if grace period has expired
		if contract.GracePeriodEnd != nil && time.Now().After(*contract.GracePeriodEnd) {
			contract.RequirementsMet = false
			SuspendServiceDelivery(contract, "Client no longer meets requirements")
			NotifyContractParties(contract, "Service suspended due to requirement violation")
		} else {
			// Still within grace period - send warning
			NotifyConsumer(contract.Consumer.NodeID, fmt.Sprintf(
				"Warning: You no longer meet service requirements. Grace period ends %s",
				contract.GracePeriodEnd.Format(time.RFC3339)))
		}
	} else {
		// Requirements met again - clear violations
		if contract.ViolationCount > 0 {
			contract.ViolationCount = 0
			NotifyConsumer(contract.Consumer.NodeID, "You now meet all service requirements")
		}
	}
}
```

---

## DHT Key Patterns

Service requirements are stored in the DHT for efficient querying:

| Purpose | Key Pattern | Description |
|---------|-------------|-------------|
| Service requirements | `service:{service-id}:requirements` | Requirements for a specific service |
| Requirements by trust | `requirements:trust:{level}:{service-id}` | Services requiring specific trust level |
| Requirements by reputation | `requirements:rep:{bucket}:{service-id}` | Services by reputation threshold |
| Requirements by region | `requirements:region:{region}:{service-id}` | Services available in region |
| Open access services | `requirements:open:{service-type}` | Services with no restrictions |

### Key Format Examples

```go
// Service requirements key
func ServiceRequirementsKey(serviceID [32]byte) string {
	return fmt.Sprintf("service:%x:requirements", serviceID)
}

// Trust level index
func RequirementsTrustIndexKey(level TrustLevel, serviceID [32]byte) string {
	return fmt.Sprintf("requirements:trust:%d:%x", level, serviceID)
}

// Reputation bucket index (0.0-0.1, 0.1-0.2, ..., 0.9-1.0)
func RequirementsReputationIndexKey(minRep float64, serviceID [32]byte) string {
	bucket := int(minRep * 10)
	return fmt.Sprintf("requirements:rep:%d:%x", bucket, serviceID)
}

// Region index
func RequirementsRegionIndexKey(region string, serviceID [32]byte) string {
	return fmt.Sprintf("requirements:region:%s:%x", region, serviceID)
}

// Open access index
func OpenAccessServicesKey(serviceType ServiceType) string {
	return fmt.Sprintf("requirements:open:%s", serviceType)
}
```

---

## Search Integration

Clients can filter services by requirements compatibility:

```go
// RequirementFilter extends SearchQuery for requirement-aware searches
type RequirementFilter struct {
	// Client Attributes
	MyTrustLevel   TrustLevel
	MyReputation   float64
	MyNetworkAge   time.Duration
	MyRegion       string
	MyViolations   uint32

	// Filter Preferences
	OnlyEligible   bool  // Only show services I'm eligible for
	ShowAll        bool  // Show all services with eligibility indicators
	IncludeGrace   bool  // Include services offering grace periods
}

// FilterByRequirements filters search results based on client eligibility
func (s *dhtSearchService) FilterByRequirements(ctx context.Context, results []*ServiceAdvertisement, filter *RequirementFilter) []*EligibilityResult {
	eligibilityResults := make([]*EligibilityResult, 0)

	for _, ad := range results {
		if ad.ClientRequirements == nil {
			// No requirements - always eligible
			eligibilityResults = append(eligibilityResults, &EligibilityResult{
				Advertisement: ad,
				Eligible:      true,
				Summary:       "Open access - no restrictions",
			})
			continue
		}

		// Perform eligibility check
		eligible := checkEligibility(ad.ClientRequirements, filter)

		if filter.OnlyEligible && !eligible {
			continue // Skip ineligible services
		}

		eligibilityResults = append(eligibilityResults, &EligibilityResult{
			Advertisement:   ad,
			Eligible:        eligible,
			Requirements:    ad.ClientRequirements,
			Summary:         ad.RequirementsSummary,
			FailureReasons:  generateFailureReasons(ad.ClientRequirements, filter),
			CanRequestGrace: eligible || ad.ClientRequirements.EnforcementLevel == EnforcementGracePeriod,
		})
	}

	return eligibilityResults
}

// EligibilityResult combines advertisement with eligibility information
type EligibilityResult struct {
	Advertisement   *ServiceAdvertisement
	Eligible        bool
	Requirements    *ServiceRequirements
	Summary         string
	FailureReasons  []string
	CanRequestGrace bool
}

func checkEligibility(req *ServiceRequirements, filter *RequirementFilter) bool {
	if filter.MyTrustLevel < req.MinTrustLevel {
		return false
	}

	if filter.MyReputation < req.MinReputation {
		return false
	}

	if filter.MyViolations > req.MaxViolations {
		return false
	}

	if filter.MyNetworkAge < req.MinNetworkAge {
		return false
	}

	// Check geography
	if len(req.BlockedRegions) > 0 && contains(req.BlockedRegions, filter.MyRegion) {
		return false
	}

	if len(req.AllowedRegions) > 0 && !contains(req.AllowedRegions, filter.MyRegion) {
		return false
	}

	return true
}
```

---

## Client User Experience

Clear communication of requirements to potential clients:

### Service Discovery Display

```
SERVICE: High-Performance Compute Cluster
Provider: TrustedCompute Inc. (Reputation: 0.92)
Price: 0.50 DHT/CPU-hour

CLIENT REQUIREMENTS:
  ✓ Trust Level: Trusted nodes only (Hardware TPM required)
  ✓ Minimum Reputation: 0.70 (Standard trust level)
  ✓ Network Age: 30 days minimum
  ✓ Geographic Regions: US, EU, Asia-Pacific
  ✗ Maximum Violations: 5 (You have 12 violations)

YOUR ELIGIBILITY: Not Eligible

REASONS:
  - Your violation count (12) exceeds maximum allowed (5)

RECOMMENDATION:
  Continue maintaining good network behavior to reduce violations.
  Estimated time to eligibility: 45 days

ALTERNATIVE OPTIONS:
  - Request grace period access (provider may grant temporary access)
  - Search for services with lower requirements
  - Contact provider for exemption consideration
```

### Contract Negotiation Flow

```
                 CONTRACT NEGOTIATION WITH REQUIREMENTS

Client                      DHT Network                    Provider
------                      -----------                    --------

  |                              |                            |
  | 1. Request Contract          |                            |
  |----------------------------->|                            |
  |                              |                            |
  |                              | 2. Check Requirements      |
  |                              |--------------------------->|
  |                              |                            |
  |                              | 3. Verify Client           |
  |                              |    - Trust Level           |
  |                              |    - Reputation            |
  |                              |    - Network Age           |
  |                              |    - Geography             |
  |                              |                            |
  |                        +-----+-----+                      |
  |                        | ELIGIBLE? |                      |
  |                        +-----+-----+                      |
  |                              |                            |
  |                      YES     |     NO                     |
  |                              |                            |
  | 4. Contract Accepted         |   4. Requirements Not Met  |
  |<-----------------------------|<---------------------------|
  |                              |   (with detailed reasons)  |
  |                              |                            |
```

---

## Recommended Requirement Configurations

Common configurations by service sensitivity:

### Public Services (Open Access)

```go
openAccessConfig := ServiceRequirements{
	MinTrustLevel:     TrustLevelUntrusted,
	MinReputation:     0.0,
	MaxViolations:     ^uint32(0),
	VerificationMode:  VerifyAtContract,
	EnforcementLevel:  EnforcementAdvisory,
}
```

**Use Case**: Public content delivery, community services, informational APIs

### Consumer Services (Basic Trust)

```go
consumerServicesConfig := ServiceRequirements{
	MinTrustLevel:     TrustLevelUntrusted,
	MinReputation:     0.50,
	MaxViolations:     10,
	MinNetworkAge:     7 * 24 * time.Hour,
	VerificationMode:  VerifyAtContract | VerifyAtAccess,
	EnforcementLevel:  EnforcementStrict,
}
```

**Use Case**: E-commerce, paid content, basic SaaS

### Business Services (Standard Trust)

```go
businessServicesConfig := ServiceRequirements{
	MinTrustLevel:     TrustLevelTrusted,
	RequireHardwareTPM: true,
	MinReputation:     0.70,
	MaxViolations:     5,
	MinNetworkAge:     30 * 24 * time.Hour,
	VerificationMode:  VerifyAll,
	EnforcementLevel:  EnforcementStrict,
}
```

**Use Case**: Business hosting, enterprise compute, data storage

### Financial Services (High Trust)

```go
financialServicesConfig := ServiceRequirements{
	MinTrustLevel:     TrustLevelTrusted,
	RequireHardwareTPM: true,
	MinReputation:     0.80,
	MaxViolations:     2,
	MinNetworkAge:     90 * 24 * time.Hour,
	VerificationMode:  VerifyAll,
	EnforcementLevel:  EnforcementStrict,
}
```

**Use Case**: Payment processing, cryptocurrency services, escrow

### Critical Infrastructure (Maximum Security)

```go
criticalInfraConfig := ServiceRequirements{
	MinTrustLevel:     TrustLevelTrusted,
	RequireHardwareTPM: true,
	MinReputation:     0.95,
	MaxViolations:     0,
	MinNetworkAge:     180 * 24 * time.Hour,
	VerificationMode:  VerifyAll,
	EnforcementLevel:  EnforcementStrict,
}
```

**Use Case**: Government services, critical infrastructure, highly sensitive data

---

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Requirement verification latency | ~50ms |
| Periodic recheck interval | 24 hours (configurable) |
| Requirements cache TTL | 1 hour |
| Search filter overhead | ~5ms per service |
| DHT requirement lookup | ~150ms per hop |
| Contract negotiation overhead | ~100ms |

---

## Security Considerations

### Requirement Spoofing Prevention

1. **Cryptographic Integrity**: Requirements hash stored in advertisement signature
2. **DHT Consistency**: Requirements stored at multiple DHT nodes
3. **Provider Verification**: Requirements verified against provider's IDevID signature
4. **Audit Trail**: All requirement changes logged in DHT

### Privacy Protections

1. **Client Anonymity**: Eligibility checks don't reveal client identity to provider until contract
2. **Requirement Opacity**: Clients see requirements but providers don't see client attributes until verification
3. **Selective Disclosure**: Clients can choose to reveal only necessary attributes

### Attack Mitigation

| Attack Vector | Mitigation |
|---------------|------------|
| Requirement bypassing | Verification at multiple checkpoints (advertisement, contract, access) |
| False eligibility claims | Client attributes verified against DHT reputation service |
| Requirement manipulation | Requirements hash in signed advertisement |
| Privacy leakage | Client attributes not disclosed until necessary |
| Exemption list abuse | Exemption lists cryptographically signed by provider |

---

## Related Documents

- [03-security-trust.md](03-security-trust.md) - Trust model and TPM requirements
- [09-defense-reputation.md](09-defense-reputation.md) - Reputation system and role eligibility
- [13-service-discovery.md](13-service-discovery.md) - Service marketplace and advertisement
- [19-service-contracts.md](19-service-contracts.md) - ServiceContract structure and lifecycle
- [17-untrusted-nodes.md](17-untrusted-nodes.md) - Untrusted node work assignments

---

**Document Version:** 1.0
**Last Updated:** 2026-01-09
**Status:** Production Specification
