# AI-Based Arbitration System

> **Status: PLANNED** · Scope: design only, no implementation · Last verified: 2026-10-20

This document specifies the AI-based arbitration system for ServiceContracts in go-trusted-platform DHT, enabling AI agents with capability certificates to serve as arbitrators alongside human arbiters.

---

## Executive Summary

The AI Arbitration System extends the existing ServiceContract dispute resolution framework to support three arbitration modes: human-only, AI-only, and hybrid. AI arbitrators are TPM-bound agents running on trusted nodes with specific capability certificates for dispute resolution. The system provides deterministic, auditable decisions with structured reasoning while maintaining the option to appeal to human arbiters.

**Key Features:**
- TPM-bound AI arbitrators with capability certificates
- Three-tier arbitration model (Human, AI, Hybrid)
- Structured evidence evaluation and reasoning
- Deterministic decisions with cryptographic audit trails
- Appeal process from AI to human arbiters
- VRF-based selection for both AI and human arbiters

---

## Architecture Overview

The AI Arbitration System consists of the following components:

```
+---------------------------------------------------------------------+
|                    SERVICE CONTRACT ARBITRATION                     |
+---------------------------------------------------------------------+
                                 |
                 +---------------+---------------+
                 |                               |
        +--------v--------+             +--------v--------+
        |  Human          |             |   AI            |
        |  Arbitration    |             |   Arbitration   |
        |  (Traditional)  |             |   (Automated)   |
        +--------+--------+             +--------+--------+
                 |                               |
                 +---------------+---------------+
                                 |
                         +-------v-------+
                         | Hybrid        |
                         | Arbitration   |
                         | (AI + Human)  |
                         +---------------+


                    AI ARBITRATOR COMPONENTS

+------------------------------------------------------------------+
|                      TPM-BOUND AI AGENT                          |
|  +------------------------------------------------------------+  |
|  |  Agent Identity (SHA256(NodeIDevID || Instance || Nonce))  |  |
|  +------------------------------------------------------------+  |
|  |  Capability Certificates:                                  |  |
|  |    - CapTypeDisputeAnalysis                                |  |
|  |    - CapTypeEvidenceEvaluation                             |  |
|  |    - CapTypeArbitration (required)                         |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
                                |
                                v
+------------------------------------------------------------------+
|              AI ARBITRATION DECISION ENGINE                      |
|  +------------------------------------------------------------+  |
|  |  1. Evidence Collection & Structuring                      |  |
|  |  2. Claim Extraction & Categorization                      |  |
|  |  3. Evidence Evaluation (objective metrics)                |  |
|  |  4. Decision Generation (structured reasoning)             |  |
|  |  5. Confidence Assessment                                  |  |
|  |  6. Appeal Recommendation                                  |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
                                |
                                v
+------------------------------------------------------------------+
|                    DISPUTE RESOLUTION                            |
|  +------------------------------------------------------------+  |
|  |  Outcome:                                                  |  |
|  |    - Provider Wins / Consumer Wins / Split                 |  |
|  |  Reasoning:                                                |  |
|  |    - Structured JSON with evidence references              |  |
|  |  Confidence: 0.0 - 1.0                                     |  |
|  |  Appeal: Automatic if confidence < threshold               |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

**Data Flow:**

1. Consumer creates ServiceContract with `ArbitratorType` selection
2. Dispute opened → VRF selects arbitrators (AI or human based on type)
3. Evidence submitted by both parties
4. AI arbitrators evaluate evidence using structured analysis
5. Decision generated with confidence score and reasoning
6. Low-confidence decisions automatically escalate to human review
7. Final decision executed on escrow

---

## Service Definitions

### AI Arbitrator Service

The AI Arbitrator Service manages the lifecycle of AI agents authorized to arbitrate disputes:

**Core Responsibilities:**
- Register AI agents with arbitration capabilities
- Validate capability certificates and TPM attestation
- Maintain arbitrator pool with reputation tracking
- Evaluate evidence and generate structured decisions
- Provide audit trails for all decisions

**Service Endpoints:**
- `RegisterArbitrator(agentID, capabilities, attestation)` - Register AI arbitrator
- `EvaluateDispute(disputeID, evidence)` - Evaluate dispute and render decision
- `GetArbitratorReputation(agentID)` - Query arbitrator performance
- `AppealToHuman(disputeID, reason)` - Escalate to human review

---

## API Contracts

### 1. ArbitratorType Enum

```go
// ArbitratorType defines the type of arbitrator for dispute resolution
type ArbitratorType uint8

const (
    ArbitratorTypeHuman  ArbitratorType = 1 // Human arbiters only (VRF-selected pool)
    ArbitratorTypeAI     ArbitratorType = 2 // AI agents only (VRF-selected pool)
    ArbitratorTypeHybrid ArbitratorType = 3 // AI pre-screening with human final decision
)

// String returns human-readable arbitrator type
func (at ArbitratorType) String() string {
    switch at {
    case ArbitratorTypeHuman:
        return "human"
    case ArbitratorTypeAI:
        return "ai"
    case ArbitratorTypeHybrid:
        return "hybrid"
    default:
        return "unknown"
    }
}

// Validate ensures arbitrator type is valid
func (at ArbitratorType) Validate() error {
    if at < ArbitratorTypeHuman || at > ArbitratorTypeHybrid {
        return ErrInvalidArbitratorType{Type: at}
    }
    return nil
}
```

**REST Endpoint:**
```
POST /contracts/{contractID}/dispute/arbitrator-type
```

**Request:**
```json
{
  "arbitratorType": "ai",
  "fallbackToHuman": true,
  "confidenceThreshold": 0.85
}
```

**Response (200 OK):**
```json
{
  "contractID": "0x1234...",
  "arbitratorType": "ai",
  "selectedArbitrators": [
    {
      "agentID": "0xabcd...",
      "capabilities": ["arbitration", "evidence_evaluation"],
      "reputation": 0.92,
      "trustLevel": "trusted"
    }
  ],
  "fallbackEnabled": true,
  "confidenceThreshold": 0.85
}
```

**Error Response (400 Bad Request):**
```json
{
  "error": "invalid_arbitrator_type",
  "message": "Arbitrator type must be human, ai, or hybrid",
  "validTypes": ["human", "ai", "hybrid"]
}
```

### 2. AIArbitratorConfig Structure

```go
// AIArbitratorConfig defines configuration for AI-based arbitration
type AIArbitratorConfig struct {
    // Arbitrator Selection
    MinReputation         float64           // Minimum reputation for AI arbitrators (0.85 default)
    MinArbitrationCount   uint64            // Minimum prior arbitrations (50 default)
    RequiredCapabilities  []CapabilityType  // Required capability certificates

    // Decision Parameters
    ConfidenceThreshold   float64           // Minimum confidence for final decision (0.80 default)
    AutoAppealThreshold   float64           // Auto-escalate to human if below (0.70 default)
    MaxProcessingTime     time.Duration     // Maximum time for decision (5 minutes default)

    // Evidence Processing
    MaxEvidenceSize       uint64            // Maximum evidence size in bytes (10MB default)
    SupportedFormats      []string          // Supported evidence formats
    RequireStructured     bool              // Require structured evidence format

    // Appeal Configuration
    AllowAppeal           bool              // Allow appeal to human arbiters
    AppealWindow          time.Duration     // Window to file appeal (72h default)
    AppealFee             uint64            // Fee to file appeal

    // Audit and Transparency
    PublishReasoning      bool              // Publish detailed reasoning
    RequireExplanation    bool              // Require explanation for each decision point
    AuditLogRetention     time.Duration     // How long to retain audit logs (2 years)

    // Multi-Arbitrator Settings (for AI pools)
    ArbiterCount          uint8             // Number of AI arbitrators (3 default)
    QuorumRequired        uint8             // Votes needed for decision (2 default)
    AllowDisagreement     bool              // Allow arbitrators to disagree
}

// DefaultAIArbitratorConfig provides sensible defaults
var DefaultAIArbitratorConfig = AIArbitratorConfig{
    MinReputation:         0.85,
    MinArbitrationCount:   50,
    RequiredCapabilities: []CapabilityType{
        CapTypeArbitration,
        CapTypeEvidenceEvaluation,
    },
    ConfidenceThreshold:   0.80,
    AutoAppealThreshold:   0.70,
    MaxProcessingTime:     5 * time.Minute,
    MaxEvidenceSize:       10 * 1024 * 1024, // 10MB
    SupportedFormats:      []string{"json", "yaml", "text"},
    RequireStructured:     false,
    AllowAppeal:           true,
    AppealWindow:          72 * time.Hour,
    AppealFee:             100, // tokens
    PublishReasoning:      true,
    RequireExplanation:    true,
    AuditLogRetention:     2 * 365 * 24 * time.Hour,
    ArbiterCount:          3,
    QuorumRequired:        2,
    AllowDisagreement:     true,
}

// Validate ensures configuration is valid
func (c *AIArbitratorConfig) Validate() error {
    if c.MinReputation < 0.0 || c.MinReputation > 1.0 {
        return ErrInvalidReputationThreshold
    }
    if c.ConfidenceThreshold < 0.0 || c.ConfidenceThreshold > 1.0 {
        return ErrInvalidConfidenceThreshold
    }
    if c.AutoAppealThreshold >= c.ConfidenceThreshold {
        return ErrInvalidAppealThreshold
    }
    if c.QuorumRequired > c.ArbiterCount {
        return ErrInvalidQuorum
    }
    if len(c.RequiredCapabilities) == 0 {
        return ErrNoRequiredCapabilities
    }
    return nil
}
```

**REST Endpoint:**
```
PUT /contracts/{contractID}/ai-arbitrator-config
```

**Request:**
```json
{
  "minReputation": 0.85,
  "minArbitrationCount": 50,
  "requiredCapabilities": ["arbitration", "evidence_evaluation"],
  "confidenceThreshold": 0.80,
  "autoAppealThreshold": 0.70,
  "maxProcessingTime": "5m",
  "allowAppeal": true,
  "appealWindow": "72h"
}
```

**Response (200 OK):**
```json
{
  "contractID": "0x1234...",
  "config": {
    "minReputation": 0.85,
    "confidenceThreshold": 0.80,
    "arbiterCount": 3,
    "quorumRequired": 2
  },
  "validated": true
}
```

### 3. AIArbitratorAgent Identity

```go
// AIArbitratorAgent represents an AI agent with arbitration capability
type AIArbitratorAgent struct {
    // Agent Identity (inherited from AgentIdentity)
    AgentID        [32]byte           // SHA256(NodeIDevID || Instance || Nonce)
    HostNodeID     [32]byte           // TPM-bound host node
    IDevIDCertHash [32]byte           // Hash of host IDevID certificate

    // TPM Binding
    AgentKeyHandle uint32             // TPM handle for agent-specific key
    PCRExtension   []byte             // Agent code hash in PCR[15]
    TrustLevel     TrustLevel         // Inherited from host (must be Trusted)

    // Arbitration-Specific Identity
    ArbitratorID   [32]byte           // Unique arbitrator identifier
    Specialization []DisputeCategory  // Types of disputes this agent handles

    // Capability Certificates
    Capabilities   []AgentCapability  // Must include CapTypeArbitration
    CapabilityCert *x509.Certificate  // CA-signed capability certificate

    // Model and Runtime
    ModelType      ModelType          // AI model family
    ModelVersion   string             // Specific model version
    ModelHash      [32]byte           // Hash of model weights
    RuntimeHash    [32]byte           // Hash of arbitration runtime

    // Arbitration Metadata
    CasesHandled   uint64             // Total cases arbitrated
    Reputation     float64            // Arbitrator reputation (0.0-1.0)
    SuccessRate    float64            // Decisions upheld on appeal
    AvgConfidence  float64            // Average confidence score

    // Operational Constraints
    MaxConcurrentCases uint8          // Maximum concurrent cases
    ResponseTime       time.Duration  // Typical response time

    // Registration
    RegisteredAt   time.Time
    LastAttestation time.Time         // Last TPM attestation
    CertExpiry     time.Time          // Capability certificate expiry

    // Signatures
    AgentSignature []byte             // Agent's signature
    HostSignature  []byte             // Host node's IDevID signature
}

// DisputeCategory defines types of disputes an arbitrator can handle
type DisputeCategory uint8

const (
    DisputeCategoryServiceDelivery DisputeCategory = 1  // Service not delivered
    DisputeCategoryQuality         DisputeCategory = 2  // Quality disputes
    DisputeCategorySLA             DisputeCategory = 3  // SLA violations
    DisputeCategoryPayment         DisputeCategory = 4  // Payment disputes
    DisputeCategoryTermination     DisputeCategory = 5  // Early termination
    DisputeCategoryMiscellaneous   DisputeCategory = 6  // Other disputes
)

// VerifyArbitratorIdentity validates the AI arbitrator's identity chain
func VerifyArbitratorIdentity(agent *AIArbitratorAgent) error {
    // 1. Verify trust level is Trusted (untrusted agents cannot arbitrate)
    if agent.TrustLevel != TrustLevelTrusted {
        return ErrUntrustedArbitrator{AgentID: agent.AgentID}
    }

    // 2. Verify host node's IDevID certificate
    hostIDevID, err := FetchIDevIDCertificate(agent.IDevIDCertHash)
    if err != nil {
        return ErrIDevIDNotFound{Hash: agent.IDevIDCertHash}
    }

    // 3. Verify IDevID chains to DHT Privacy CA
    if err := VerifyCertificateChain(hostIDevID, agent.HostNodeID); err != nil {
        return ErrCertificateChainInvalid{Cause: err}
    }

    // 4. Verify capability certificate contains CapTypeArbitration
    hasArbitrationCap := false
    for _, cap := range agent.Capabilities {
        if cap.Type == CapTypeArbitration {
            hasArbitrationCap = true
            break
        }
    }
    if !hasArbitrationCap {
        return ErrMissingArbitrationCapability
    }

    // 5. Verify capability certificate is not expired
    if time.Now().After(agent.CertExpiry) {
        return ErrCapabilityCertExpired
    }

    // 6. Verify fresh TPM attestation (within last 24 hours)
    if time.Since(agent.LastAttestation) > 24*time.Hour {
        return ErrStaleAttestation
    }

    // 7. Verify minimum reputation threshold
    if agent.Reputation < DefaultAIArbitratorConfig.MinReputation {
        return ErrInsufficientReputation{
            Required: DefaultAIArbitratorConfig.MinReputation,
            Actual:   agent.Reputation,
        }
    }

    // 8. CRITICAL (P4-M8): Verify model hash against approved whitelist
    if err := VerifyModelHashAgainstWhitelist(agent.ModelHash, agent.ModelType); err != nil {
        return err
    }

    return nil
}

### Approved Model Whitelist (P4-M8 Fix)

**Problem**: ModelHash field exists but is NEVER verified against an approved list.
Attackers could register arbitrators with poisoned or biased models.

**Solution**: Maintain a CA-managed whitelist of approved model hashes with
governance process for additions.

```go
// ModelWhitelist manages approved AI models for arbitration
type ModelWhitelist struct {
    mu            sync.RWMutex
    approvedModels map[[32]byte]*ApprovedModel
    lastUpdate    time.Time
    version       uint64
}

// ApprovedModel represents an approved AI model for arbitration
type ApprovedModel struct {
    // Identity
    ModelHash      [32]byte    // SHA256 of model weights
    ModelType      ModelType   // Model family (claude, gpt, etc.)
    ModelVersion   string      // Specific version string
    RuntimeHash    [32]byte    // Expected runtime hash (optional)

    // Approval Metadata
    ApprovedAt     time.Time
    ApprovedBy     [32]byte    // CA operator who approved
    ApprovalTxID   [32]byte    // DHT transaction ID for audit

    // Capabilities
    AllowedCategories []DisputeCategory  // Which dispute types this model can handle
    MaxConfidence     float64            // Maximum confidence score allowed (prevent overconfidence)
    BiasProfile       *BiasProfile       // Known biases (if any)

    // Validity
    ValidFrom      time.Time
    ValidUntil     time.Time   // Expiry for time-limited approvals
    Revoked        bool
    RevocationReason string

    // Governance
    GovernanceProposal [32]byte  // Link to governance proposal (if required)
    VotesFor          uint64
    VotesAgainst      uint64
}

// BiasProfile documents known biases in a model
type BiasProfile struct {
    ProviderBias     float64  // Bias toward provider (0.5 = neutral)
    ConsumerBias     float64  // Bias toward consumer (0.5 = neutral)
    CategoryBiases   map[DisputeCategory]float64  // Category-specific biases
    MitigationNotes  string   // How to mitigate known biases
    LastAssessed     time.Time
}

// ModelType enumeration
type ModelType uint8
const (
    ModelTypeClaude    ModelType = 1
    ModelTypeGPT       ModelType = 2
    ModelTypeGemini    ModelType = 3
    ModelTypeLlama     ModelType = 4
    ModelTypeMistral   ModelType = 5
    ModelTypeCustom    ModelType = 255
)

// VerifyModelHashAgainstWhitelist checks if model is approved for arbitration
// SECURITY (P4-M8): This is mandatory for all AI arbitrators
func VerifyModelHashAgainstWhitelist(modelHash [32]byte, modelType ModelType) error {
    whitelist := GetGlobalModelWhitelist()

    whitelist.mu.RLock()
    defer whitelist.mu.RUnlock()

    model, exists := whitelist.approvedModels[modelHash]
    if !exists {
        return &ErrModelNotApproved{
            ModelHash: modelHash,
            Reason:    "model hash not found in approved whitelist",
        }
    }

    // Verify model type matches
    if model.ModelType != modelType {
        return &ErrModelNotApproved{
            ModelHash: modelHash,
            Reason:    fmt.Sprintf("model type mismatch: expected %v, got %v", model.ModelType, modelType),
        }
    }

    // Verify model is not revoked
    if model.Revoked {
        return &ErrModelNotApproved{
            ModelHash: modelHash,
            Reason:    fmt.Sprintf("model revoked: %s", model.RevocationReason),
        }
    }

    // Verify model is within validity period
    now := time.Now()
    if now.Before(model.ValidFrom) {
        return &ErrModelNotApproved{
            ModelHash: modelHash,
            Reason:    "model approval not yet effective",
        }
    }

    if now.After(model.ValidUntil) {
        return &ErrModelNotApproved{
            ModelHash: modelHash,
            Reason:    "model approval expired",
        }
    }

    return nil
}

// GetAllowedCategories returns dispute categories this model can handle
func (w *ModelWhitelist) GetAllowedCategories(modelHash [32]byte) ([]DisputeCategory, error) {
    w.mu.RLock()
    defer w.mu.RUnlock()

    model, exists := w.approvedModels[modelHash]
    if !exists {
        return nil, &ErrModelNotApproved{ModelHash: modelHash, Reason: "model not found"}
    }

    return model.AllowedCategories, nil
}

// Model Governance Functions

// ProposeModelApproval initiates governance proposal to approve a new model
func ProposeModelApproval(
    modelHash [32]byte,
    modelType ModelType,
    modelVersion string,
    categories []DisputeCategory,
    proposer [32]byte,
) (*GovernanceProposal, error) {
    // Create governance proposal
    proposal := &GovernanceProposal{
        ProposalID:   sha256.Sum256(append(modelHash[:], proposer[:]...)),
        Type:         ProposalTypeModelApproval,
        Proposer:     proposer,
        CreatedAt:    time.Now(),
        VotingEnds:   time.Now().Add(7 * 24 * time.Hour), // 7 day voting period
        QuorumNeeded: 0.5,  // 50% of voting power
        Payload: &ModelApprovalPayload{
            ModelHash:   modelHash,
            ModelType:   modelType,
            ModelVersion: modelVersion,
            Categories:  categories,
        },
    }

    // Submit to governance system
    return submitGovernanceProposal(proposal)
}

// RevokeModel immediately revokes an approved model
// SECURITY: Requires CA operator authorization
func (w *ModelWhitelist) RevokeModel(
    ctx context.Context,
    modelHash [32]byte,
    reason string,
    revoker [32]byte,
) error {
    w.mu.Lock()
    defer w.mu.Unlock()

    model, exists := w.approvedModels[modelHash]
    if !exists {
        return &ErrModelNotApproved{ModelHash: modelHash, Reason: "model not found"}
    }

    model.Revoked = true
    model.RevocationReason = reason

    // Propagate revocation to DHT
    revocationRecord := &ModelRevocation{
        ModelHash:  modelHash,
        RevokedBy:  revoker,
        RevokedAt:  time.Now(),
        Reason:     reason,
    }

    // Store in DHT for persistence
    if err := storeModelRevocation(ctx, revocationRecord); err != nil {
        return fmt.Errorf("failed to persist model revocation: %w", err)
    }

    return nil
}

// LoadWhitelistFromDHT loads approved models from DHT
func (w *ModelWhitelist) LoadWhitelistFromDHT(ctx context.Context, dht DHT) error {
    // Fetch all approved model entries
    entries, err := dht.FetchPrefix(ctx, "ai:model:approved:")
    if err != nil {
        return fmt.Errorf("failed to load model whitelist: %w", err)
    }

    w.mu.Lock()
    defer w.mu.Unlock()

    for _, entry := range entries {
        var model ApprovedModel
        if err := decodeModel(entry.Value, &model); err != nil {
            continue // Skip corrupted entries
        }
        w.approvedModels[model.ModelHash] = &model
    }

    w.lastUpdate = time.Now()
    return nil
}

// Model whitelist errors
type ErrModelNotApproved struct {
    ModelHash [32]byte
    Reason    string
}

func (e *ErrModelNotApproved) Error() string {
    return fmt.Sprintf("model %x not approved: %s", e.ModelHash[:8], e.Reason)
}

// DHT Keys for Model Whitelist
// ai:model:approved:{model-hash}   -> ApprovedModel
// ai:model:revoked:{model-hash}    -> ModelRevocation
// ai:model:proposal:{proposal-id}  -> GovernanceProposal

// Default approved models (bootstrap - governance can add more)
var BootstrapApprovedModels = []ApprovedModel{
    // Note: These are placeholder hashes - actual hashes computed from real model weights
    {
        ModelType:    ModelTypeClaude,
        ModelVersion: "claude-3-opus-20240229",
        AllowedCategories: []DisputeCategory{
            DisputeCategoryServiceDelivery,
            DisputeCategoryQuality,
            DisputeCategorySLA,
            DisputeCategoryPayment,
            DisputeCategoryTermination,
            DisputeCategoryMiscellaneous,
        },
        MaxConfidence: 0.95,
        BiasProfile: &BiasProfile{
            ProviderBias: 0.50, // Neutral
            ConsumerBias: 0.50, // Neutral
        },
        ValidFrom:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
        ValidUntil: time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
    },
}

// Global whitelist singleton
var globalModelWhitelist *ModelWhitelist
var whitelistOnce sync.Once

func GetGlobalModelWhitelist() *ModelWhitelist {
    whitelistOnce.Do(func() {
        globalModelWhitelist = &ModelWhitelist{
            approvedModels: make(map[[32]byte]*ApprovedModel),
        }
        // Load bootstrap models
        for _, model := range BootstrapApprovedModels {
            globalModelWhitelist.approvedModels[model.ModelHash] = &model
        }
    })
    return globalModelWhitelist
}
```

// RequiresFreshAttestation checks if agent needs new TPM attestation
func (a *AIArbitratorAgent) RequiresFreshAttestation() bool {
    return time.Since(a.LastAttestation) > 24*time.Hour
}
```

**REST Endpoint:**
```
POST /arbitrators/register
```

**Request:**
```json
{
  "agentID": "0xabcd...",
  "hostNodeID": "0x5678...",
  "capabilities": [
    {
      "type": "arbitration",
      "constraints": {
        "maxConcurrentCases": 10,
        "specializations": ["service_delivery", "sla_violations"]
      }
    },
    {
      "type": "evidence_evaluation",
      "constraints": {
        "supportedFormats": ["json", "text", "structured"]
      }
    }
  ],
  "tpmAttestation": {
    "quote": "0x...",
    "pcrValues": {"15": "0x..."},
    "nonce": "0x..."
  },
  "capabilityCert": "-----BEGIN CERTIFICATE-----\n..."
}
```

**Response (201 Created):**
```json
{
  "arbitratorID": "0x9abc...",
  "agentID": "0xabcd...",
  "trustLevel": "trusted",
  "reputation": 0.00,
  "casesHandled": 0,
  "specializations": ["service_delivery", "sla_violations"],
  "certExpiry": "2026-01-09T12:00:00Z",
  "registeredAt": "2026-01-09T00:00:00Z"
}
```

**Error Response (403 Forbidden):**
```json
{
  "error": "untrusted_agent",
  "message": "AI arbitrators must be running on trusted nodes with hardware TPM",
  "agentID": "0xabcd...",
  "hostTrustLevel": "untrusted"
}
```

### 4. AIArbitrationProcess Flow

```go
// AIArbitrationProcess defines the end-to-end arbitration workflow
type AIArbitrationProcess struct {
    ProcessID       [32]byte           // Unique process identifier
    ContractID      [32]byte           // Associated service contract
    DisputeID       [32]byte           // Dispute being arbitrated

    // Arbitrators
    Arbitrators     []AIArbitratorAgent // Selected AI arbitrators
    QuorumRequired  uint8              // Votes needed for decision

    // Evidence
    Evidence        *DisputeEvidence   // Collected evidence
    EvidenceHash    [32]byte           // Hash of all evidence

    // Process State
    Stage           ArbitrationStage   // Current stage
    StartedAt       time.Time
    CompletedAt     *time.Time

    // Analysis Results
    Analysis        *EvidenceAnalysis  // Structured evidence analysis
    Decisions       []ArbitratorVote   // Individual arbitrator decisions
    FinalDecision   *AIArbitrationDecision // Consensus decision

    // Audit Trail
    AuditLog        []AuditEntry       // Complete process audit log
    SignedTranscript []byte            // Cryptographically signed transcript
}

// ArbitrationStage represents process progress
type ArbitrationStage uint8

const (
    StageEvidenceCollection ArbitrationStage = 1 // Collecting evidence
    StageAnalysis           ArbitrationStage = 2 // Analyzing evidence
    StageDeliberation       ArbitrationStage = 3 // Arbitrators deliberating
    StageDecision           ArbitrationStage = 4 // Final decision rendered
    StageAppeal             ArbitrationStage = 5 // Appeal filed
    StageClosed             ArbitrationStage = 6 // Process closed
)

// DisputeEvidence contains all evidence submitted by parties
type DisputeEvidence struct {
    DisputeID       [32]byte

    // Provider Evidence
    ProviderClaims  []Claim            // Provider's claims
    ProviderProof   []EvidenceItem     // Provider's supporting evidence

    // Consumer Evidence
    ConsumerClaims  []Claim            // Consumer's claims
    ConsumerProof   []EvidenceItem     // Consumer's supporting evidence

    // Objective Evidence (from automation)
    SLAMetrics      map[string]float64 // Measured SLA metrics
    ServiceLogs     []ServiceLogEntry  // Service execution logs
    TransactionLogs []TransactionEntry // Payment/escrow transactions

    // Deadlines
    SubmissionDeadline time.Time
    AllEvidenceSubmitted bool
}

// Claim represents a party's assertion
type Claim struct {
    ClaimID         [16]byte
    PartyID         [32]byte           // Provider or Consumer
    ClaimType       ClaimType
    Description     string
    AssertedValue   interface{}        // What party claims
    SupportingEvidence [][32]byte      // References to evidence items
    Timestamp       time.Time
}

// ClaimType categorizes dispute claims
type ClaimType uint8

const (
    ClaimServiceNotDelivered   ClaimType = 1  // Service was not delivered
    ClaimServiceIncomplete     ClaimType = 2  // Service partially delivered
    ClaimQualityInadequate     ClaimType = 3  // Service quality below standard
    ClaimSLAViolation          ClaimType = 4  // SLA terms breached
    ClaimPaymentNotReceived    ClaimType = 5  // Payment not made
    ClaimUnauthorizedTermination ClaimType = 6 // Contract terminated improperly
)

// EvidenceItem represents a piece of evidence
// SECURITY FIX (P4-C12): Evidence MUST be bound to ContractID + DisputeID
// to prevent cross-contract evidence reuse attacks
type EvidenceItem struct {
    EvidenceID      [32]byte

    // CRITICAL: Binding fields prevent evidence reuse across disputes
    ContractID      [32]byte           // Bound to specific contract (REQUIRED)
    DisputeID       [32]byte           // Bound to specific dispute (REQUIRED)

    Type            EvidenceType
    Format          string             // "json", "text", "binary"
    Content         []byte
    ContentHash     [32]byte           // SHA256(Content)
    SubmittedBy     [32]byte           // Party who submitted (IDevID hash)
    SubmittedByPubKey []byte           // Public key for signature verification
    Timestamp       time.Time

    // Signature covers: ContractID || DisputeID || ContentHash || SubmittedBy || Timestamp
    // Algorithm: Ed25519 (MUST use Ed25519 - no algorithm agility)
    Signature       []byte
    SignatureAlgorithm string          // MUST be "Ed25519" - validated on submission

    Verified        bool               // Whether evidence was verified
    VerifiedAt      time.Time          // When verification occurred
    VerifiedBy      [32]byte           // Verifier node ID
}

// EvidencePacket represents a complete, immutable evidence submission with TPM attestation
// This is the canonical structure for submitting evidence to a dispute
type EvidencePacket struct {
    // Identity
    EvidenceID      [32]byte           // SHA256(CollectorID || ContractID || DisputeID || ContentHash)

    // Collector Information
    CollectorID     [32]byte           // Node ID of evidence collector
    CollectedAt     time.Time          // When evidence was collected

    // Contract and Dispute Binding (CRITICAL for preventing reuse)
    ContractID      [32]byte           // Bound to specific contract
    DisputeID       [32]byte           // Bound to specific dispute

    // Content
    ContentHash     [32]byte           // SHA256 of Content
    Content         []byte             // Actual evidence data

    // TPM Attestation (REQUIRED for trusted evidence)
    TPMAttestation  *TPMEvidenceAttestation

    // Cryptographic Signature (Ed25519 ONLY - no algorithm agility)
    // Signs: EvidenceID || ContractID || DisputeID || ContentHash || CollectedAt
    Signature       []byte             // Ed25519 signature
    PublicKey       []byte             // Ed25519 public key for verification

    // Immutability Flag
    Immutable       bool               // Once set to true, evidence cannot be modified
    ImmutableAt     time.Time          // When immutability was set
    ImmutableProof  []byte             // TPM quote proving immutability timestamp
}

// TPMEvidenceAttestation provides hardware-rooted proof of evidence integrity
type TPMEvidenceAttestation struct {
    // TPM Quote
    Quote           []byte             // TPM2_Quote result
    PCRValues       map[int][]byte     // PCR values at attestation time
    Nonce           [32]byte           // Freshness nonce

    // Attestation Key
    AIKCertHash     [32]byte           // Hash of AIK certificate
    AIKSignature    []byte             // AIK signature over quote

    // Evidence Binding in PCR
    PCRIndex        int                // PCR index where evidence hash was extended (typically PCR[14])
    ExtendedHash    [32]byte           // Hash extended to PCR

    // Timestamp
    AttestationTime time.Time
    ClockInfo       []byte             // TPM clock info for ordering
}

// ValidateEvidencePacket performs complete validation of an evidence packet
// SECURITY: This MUST be called before accepting any evidence
func ValidateEvidencePacket(packet *EvidencePacket, expectedContractID, expectedDisputeID [32]byte) error {
    // 1. Verify contract and dispute binding
    if packet.ContractID != expectedContractID {
        return ErrEvidenceContractMismatch{
            Expected: expectedContractID,
            Actual:   packet.ContractID,
        }
    }
    if packet.DisputeID != expectedDisputeID {
        return ErrEvidenceDisputeMismatch{
            Expected: expectedDisputeID,
            Actual:   packet.DisputeID,
        }
    }

    // 2. Verify content hash
    computedHash := sha256.Sum256(packet.Content)
    if computedHash != packet.ContentHash {
        return ErrEvidenceContentTampered{
            EvidenceID:   packet.EvidenceID,
            ExpectedHash: packet.ContentHash,
            ActualHash:   computedHash,
        }
    }

    // 3. Verify evidence ID derivation
    expectedID := deriveEvidenceID(packet.CollectorID, packet.ContractID, packet.DisputeID, packet.ContentHash)
    if expectedID != packet.EvidenceID {
        return ErrEvidenceIDMismatch{
            Expected: expectedID,
            Actual:   packet.EvidenceID,
        }
    }

    // 4. Verify Ed25519 signature
    signedData := buildEvidenceSignedData(packet)
    if !ed25519.Verify(packet.PublicKey, signedData, packet.Signature) {
        return ErrEvidenceSignatureInvalid{EvidenceID: packet.EvidenceID}
    }

    // 5. Verify TPM attestation (if present)
    if packet.TPMAttestation != nil {
        if err := verifyTPMEvidenceAttestation(packet.TPMAttestation, packet.ContentHash); err != nil {
            return ErrTPMAttestationInvalid{
                EvidenceID: packet.EvidenceID,
                Cause:      err,
            }
        }
    }

    // 6. Verify immutability constraints
    if packet.Immutable && packet.ImmutableAt.IsZero() {
        return ErrInvalidImmutabilityState{EvidenceID: packet.EvidenceID}
    }

    return nil
}

// deriveEvidenceID creates a deterministic evidence ID from binding fields
func deriveEvidenceID(collectorID, contractID, disputeID, contentHash [32]byte) [32]byte {
    h := sha256.New()
    h.Write(collectorID[:])
    h.Write(contractID[:])
    h.Write(disputeID[:])
    h.Write(contentHash[:])
    var id [32]byte
    copy(id[:], h.Sum(nil))
    return id
}

// buildEvidenceSignedData constructs the data to be signed
func buildEvidenceSignedData(packet *EvidencePacket) []byte {
    data := make([]byte, 0, 160)
    data = append(data, packet.EvidenceID[:]...)
    data = append(data, packet.ContractID[:]...)
    data = append(data, packet.DisputeID[:]...)
    data = append(data, packet.ContentHash[:]...)
    data = append(data, []byte(packet.CollectedAt.Format(time.RFC3339Nano))...)
    return data
}

// Error types for evidence packet validation
type ErrEvidenceIDMismatch struct {
    Expected, Actual [32]byte
}
func (e ErrEvidenceIDMismatch) Error() string {
    return fmt.Sprintf("evidence ID mismatch: expected %x, got %x", e.Expected[:8], e.Actual[:8])
}

type ErrTPMAttestationInvalid struct {
    EvidenceID [32]byte
    Cause      error
}
func (e ErrTPMAttestationInvalid) Error() string {
    return fmt.Sprintf("TPM attestation invalid for evidence %x: %v", e.EvidenceID[:8], e.Cause)
}

type ErrInvalidImmutabilityState struct {
    EvidenceID [32]byte
}
func (e ErrInvalidImmutabilityState) Error() string {
    return fmt.Sprintf("evidence %x marked immutable but missing timestamp", e.EvidenceID[:8])
}

// VerifyEvidenceBinding validates that evidence is properly bound and signed
// Returns error if evidence could be reused from another dispute
func VerifyEvidenceBinding(evidence *EvidenceItem, expectedContractID, expectedDisputeID [32]byte) error {
    // Check 1: Evidence is bound to correct contract
    if evidence.ContractID != expectedContractID {
        return ErrEvidenceContractMismatch{
            Expected: expectedContractID,
            Actual:   evidence.ContractID,
        }
    }

    // Check 2: Evidence is bound to correct dispute
    if evidence.DisputeID != expectedDisputeID {
        return ErrEvidenceDisputeMismatch{
            Expected: expectedDisputeID,
            Actual:   evidence.DisputeID,
        }
    }

    // Check 3: Algorithm MUST be Ed25519 (no algorithm agility attacks)
    if evidence.SignatureAlgorithm != "Ed25519" {
        return ErrInvalidSignatureAlgorithm{
            Expected: "Ed25519",
            Actual:   evidence.SignatureAlgorithm,
        }
    }

    // Check 4: Verify signature over binding fields
    signedData := make([]byte, 0, 128)
    signedData = append(signedData, evidence.ContractID[:]...)
    signedData = append(signedData, evidence.DisputeID[:]...)
    signedData = append(signedData, evidence.ContentHash[:]...)
    signedData = append(signedData, evidence.SubmittedBy[:]...)

    // Encode timestamp as RFC3339 bytes
    timestampBytes := []byte(evidence.Timestamp.Format(time.RFC3339Nano))
    signedData = append(signedData, timestampBytes...)

    // Verify Ed25519 signature
    if !ed25519.Verify(evidence.SubmittedByPubKey, signedData, evidence.Signature) {
        return ErrEvidenceSignatureInvalid{
            EvidenceID: evidence.EvidenceID,
        }
    }

    // Check 5: Verify content hash
    computedHash := sha256.Sum256(evidence.Content)
    if computedHash != evidence.ContentHash {
        return ErrEvidenceContentTampered{
            EvidenceID:   evidence.EvidenceID,
            ExpectedHash: evidence.ContentHash,
            ActualHash:   computedHash,
        }
    }

    return nil
}

// Error types for evidence validation
type ErrEvidenceContractMismatch struct {
    Expected, Actual [32]byte
}
func (e ErrEvidenceContractMismatch) Error() string {
    return fmt.Sprintf("evidence contract mismatch: expected %x, got %x", e.Expected[:8], e.Actual[:8])
}

type ErrEvidenceDisputeMismatch struct {
    Expected, Actual [32]byte
}
func (e ErrEvidenceDisputeMismatch) Error() string {
    return fmt.Sprintf("evidence dispute mismatch: expected %x, got %x", e.Expected[:8], e.Actual[:8])
}

type ErrInvalidSignatureAlgorithm struct {
    Expected, Actual string
}
func (e ErrInvalidSignatureAlgorithm) Error() string {
    return fmt.Sprintf("invalid signature algorithm: expected %s, got %s", e.Expected, e.Actual)
}

type ErrEvidenceSignatureInvalid struct {
    EvidenceID [32]byte
}
func (e ErrEvidenceSignatureInvalid) Error() string {
    return fmt.Sprintf("evidence signature invalid: %x", e.EvidenceID[:8])
}

type ErrEvidenceContentTampered struct {
    EvidenceID   [32]byte
    ExpectedHash [32]byte
    ActualHash   [32]byte
}
func (e ErrEvidenceContentTampered) Error() string {
    return fmt.Sprintf("evidence content tampered: %x (expected %x, got %x)",
        e.EvidenceID[:8], e.ExpectedHash[:8], e.ActualHash[:8])
}

// EvidenceType categorizes evidence
type EvidenceType uint8

const (
    EvidenceTypeServiceLog     EvidenceType = 1  // Service execution logs
    EvidenceTypeMetrics        EvidenceType = 2  // Performance metrics
    EvidenceTypeScreenshot     EvidenceType = 3  // Visual evidence
    EvidenceTypeTransaction    EvidenceType = 4  // Blockchain transaction
    EvidenceTypeCommunication  EvidenceType = 5  // Messages/correspondence
    EvidenceTypeAttestation    EvidenceType = 6  // Third-party attestation
    EvidenceTypeContract       EvidenceType = 7  // Contract terms
)
```

### Evidence Timestamp Integrity

Evidence timestamps are critical for establishing the timeline of events in a dispute. To prevent
backdating attacks where parties submit evidence with falsified timestamps, all evidence timestamps
require network witness attestation from multiple independent nodes.

**Key Requirements:**

| Parameter | Value | Description |
|-----------|-------|-------------|
| Minimum Witnesses | 3 | At least 3 independent nodes must attest to timestamp |
| Timestamp Variance Tolerance | 5 seconds | Maximum allowed deviation between witness attestations |
| Network Witness | Required | Evidence without network witness is rejected |
| Backdating Prevention | Enforced | Timestamps cannot predate witness attestation |

**Timestamp Attestation Process:**

1. Evidence submitter creates evidence with claimed timestamp
2. Evidence is broadcast to 3+ randomly selected witness nodes
3. Each witness independently records their observed timestamp
4. Witness nodes sign attestations including both claimed and observed timestamps
5. Evidence is only valid if all witness timestamps agree within 5-second tolerance
6. Final timestamp is the median of witness attestations

**Why Network Witness?**

Without network witness attestation, a malicious party could:
- Fabricate evidence with backdated timestamps to support false claims
- Create "evidence" after learning the outcome of events
- Manipulate the timeline to their advantage

Network witness prevents these attacks by requiring multiple independent parties to attest
to when they first observed the evidence.

```go
// EvidenceTimestampConfig defines timestamp integrity requirements
type EvidenceTimestampConfig struct {
    MinWitnessCount       int           // Minimum witnesses required (default: 3)
    TimestampTolerance    time.Duration // Maximum variance between witnesses (default: 5s)
    RequireNetworkWitness bool          // Whether network witness is mandatory (default: true)
}

// DefaultEvidenceTimestampConfig provides production defaults
var DefaultEvidenceTimestampConfig = EvidenceTimestampConfig{
    MinWitnessCount:       3,
    TimestampTolerance:    5 * time.Second,
    RequireNetworkWitness: true,
}

// TimestampWitness represents a single node's timestamp attestation
type TimestampWitness struct {
    WitnessNodeID    [32]byte           // Node providing the witness
    ClaimedTimestamp time.Time          // Timestamp claimed by submitter
    ObservedTimestamp time.Time         // Timestamp when witness received evidence
    AttestationTime  time.Time          // When attestation was created
    Signature        []byte             // Ed25519 signature of attestation
    PublicKey        []byte             // Witness node's public key
}

// EvidenceTimestampAttestation aggregates multiple witness attestations
type EvidenceTimestampAttestation struct {
    EvidenceID          [32]byte
    ContractID          [32]byte
    DisputeID           [32]byte

    // Timestamp Data
    ClaimedTimestamp    time.Time           // Original timestamp from submitter
    FinalTimestamp      time.Time           // Median of witness attestations
    TimestampVariance   time.Duration       // Maximum variance across witnesses

    // Witnesses
    Witnesses           []TimestampWitness  // Individual witness attestations
    WitnessCount        int                 // Number of valid witnesses
    AllWitnessesAgree   bool                // All within tolerance

    // Validation
    Valid               bool                // Whether timestamp is valid
    ValidationErrors    []string            // Any validation errors
}

// ValidateEvidenceTimestamp verifies timestamp has valid network witness attestation
// SECURITY: This MUST be called before accepting any evidence
func ValidateEvidenceTimestamp(
    evidence *EvidencePacket,
    attestation *EvidenceTimestampAttestation,
    config *EvidenceTimestampConfig,
) error {
    // Check 1: Network witness is required
    if config.RequireNetworkWitness && len(attestation.Witnesses) == 0 {
        return ErrNoTimestampWitness{EvidenceID: evidence.EvidenceID}
    }

    // Check 2: Minimum witness count
    if len(attestation.Witnesses) < config.MinWitnessCount {
        return ErrInsufficientTimestampWitnesses{
            EvidenceID: evidence.EvidenceID,
            Required:   config.MinWitnessCount,
            Actual:     len(attestation.Witnesses),
        }
    }

    // Check 3: Verify each witness signature
    for i, witness := range attestation.Witnesses {
        if err := verifyTimestampWitnessSignature(&witness); err != nil {
            return ErrTimestampWitnessInvalid{
                EvidenceID:    evidence.EvidenceID,
                WitnessIndex:  i,
                WitnessNodeID: witness.WitnessNodeID,
                Cause:         err,
            }
        }
    }

    // Check 4: All witnesses within tolerance
    timestamps := make([]time.Time, len(attestation.Witnesses))
    for i, w := range attestation.Witnesses {
        timestamps[i] = w.ObservedTimestamp
    }

    variance := calculateTimestampVariance(timestamps)
    if variance > config.TimestampTolerance {
        return ErrTimestampVarianceExceeded{
            EvidenceID: evidence.EvidenceID,
            Tolerance:  config.TimestampTolerance,
            Actual:     variance,
        }
    }

    // Check 5: Claimed timestamp cannot be after earliest witness observation
    // (prevents backdating by ensuring submitter didn't claim a future time)
    earliestWitness := findEarliestTimestamp(timestamps)
    if attestation.ClaimedTimestamp.After(earliestWitness) {
        return ErrTimestampBackdatingDetected{
            EvidenceID:       evidence.EvidenceID,
            ClaimedTimestamp: attestation.ClaimedTimestamp,
            EarliestWitness:  earliestWitness,
        }
    }

    // Check 6: Witnesses must be independent (different node IDs)
    if !verifyWitnessIndependence(attestation.Witnesses) {
        return ErrTimestampWitnessNotIndependent{EvidenceID: evidence.EvidenceID}
    }

    return nil
}

// RequestTimestampWitness requests timestamp attestation from network witnesses
func RequestTimestampWitness(
    evidence *EvidencePacket,
    config *EvidenceTimestampConfig,
) (*EvidenceTimestampAttestation, error) {
    // Select random witness nodes (must not include evidence submitter)
    witnesses, err := SelectRandomWitnessNodes(config.MinWitnessCount, evidence.CollectorID)
    if err != nil {
        return nil, ErrCannotSelectWitnesses{Cause: err}
    }

    attestation := &EvidenceTimestampAttestation{
        EvidenceID:       evidence.EvidenceID,
        ContractID:       evidence.ContractID,
        DisputeID:        evidence.DisputeID,
        ClaimedTimestamp: evidence.CollectedAt,
        Witnesses:        make([]TimestampWitness, 0, len(witnesses)),
    }

    // Request attestation from each witness
    for _, witnessNodeID := range witnesses {
        witness, err := requestWitnessAttestation(witnessNodeID, evidence)
        if err != nil {
            continue // Try next witness
        }
        attestation.Witnesses = append(attestation.Witnesses, *witness)
    }

    // Verify we got enough witnesses
    if len(attestation.Witnesses) < config.MinWitnessCount {
        return nil, ErrInsufficientTimestampWitnesses{
            EvidenceID: evidence.EvidenceID,
            Required:   config.MinWitnessCount,
            Actual:     len(attestation.Witnesses),
        }
    }

    // Calculate final timestamp (median of witnesses)
    attestation.FinalTimestamp = calculateMedianTimestamp(attestation.Witnesses)
    attestation.WitnessCount = len(attestation.Witnesses)
    attestation.TimestampVariance = calculateTimestampVariance(
        extractObservedTimestamps(attestation.Witnesses),
    )
    attestation.AllWitnessesAgree = attestation.TimestampVariance <= config.TimestampTolerance
    attestation.Valid = attestation.AllWitnessesAgree

    return attestation, nil
}

// calculateMedianTimestamp returns the median observed timestamp from witnesses
func calculateMedianTimestamp(witnesses []TimestampWitness) time.Time {
    if len(witnesses) == 0 {
        return time.Time{}
    }

    timestamps := make([]int64, len(witnesses))
    for i, w := range witnesses {
        timestamps[i] = w.ObservedTimestamp.UnixNano()
    }

    sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })

    mid := len(timestamps) / 2
    if len(timestamps)%2 == 0 {
        avg := (timestamps[mid-1] + timestamps[mid]) / 2
        return time.Unix(0, avg)
    }
    return time.Unix(0, timestamps[mid])
}

// calculateTimestampVariance returns the max time difference between any two witnesses
func calculateTimestampVariance(timestamps []time.Time) time.Duration {
    if len(timestamps) < 2 {
        return 0
    }

    var minTime, maxTime time.Time = timestamps[0], timestamps[0]
    for _, t := range timestamps {
        if t.Before(minTime) {
            minTime = t
        }
        if t.After(maxTime) {
            maxTime = t
        }
    }
    return maxTime.Sub(minTime)
}

// verifyWitnessIndependence ensures all witnesses are from different nodes
func verifyWitnessIndependence(witnesses []TimestampWitness) bool {
    seen := make(map[[32]byte]bool)
    for _, w := range witnesses {
        if seen[w.WitnessNodeID] {
            return false // Duplicate witness
        }
        seen[w.WitnessNodeID] = true
    }
    return true
}

// Error types for timestamp validation
type ErrNoTimestampWitness struct {
    EvidenceID [32]byte
}
func (e ErrNoTimestampWitness) Error() string {
    return fmt.Sprintf("evidence %x has no timestamp witness attestation", e.EvidenceID[:8])
}

type ErrInsufficientTimestampWitnesses struct {
    EvidenceID [32]byte
    Required   int
    Actual     int
}
func (e ErrInsufficientTimestampWitnesses) Error() string {
    return fmt.Sprintf("evidence %x has %d timestamp witnesses, requires %d",
        e.EvidenceID[:8], e.Actual, e.Required)
}

type ErrTimestampVarianceExceeded struct {
    EvidenceID [32]byte
    Tolerance  time.Duration
    Actual     time.Duration
}
func (e ErrTimestampVarianceExceeded) Error() string {
    return fmt.Sprintf("evidence %x timestamp variance %v exceeds tolerance %v",
        e.EvidenceID[:8], e.Actual, e.Tolerance)
}

type ErrTimestampBackdatingDetected struct {
    EvidenceID       [32]byte
    ClaimedTimestamp time.Time
    EarliestWitness  time.Time
}
func (e ErrTimestampBackdatingDetected) Error() string {
    return fmt.Sprintf("evidence %x backdating detected: claimed %v but earliest witness %v",
        e.EvidenceID[:8], e.ClaimedTimestamp, e.EarliestWitness)
}

type ErrTimestampWitnessInvalid struct {
    EvidenceID    [32]byte
    WitnessIndex  int
    WitnessNodeID [32]byte
    Cause         error
}
func (e ErrTimestampWitnessInvalid) Error() string {
    return fmt.Sprintf("evidence %x witness %d (node %x) invalid: %v",
        e.EvidenceID[:8], e.WitnessIndex, e.WitnessNodeID[:8], e.Cause)
}

type ErrTimestampWitnessNotIndependent struct {
    EvidenceID [32]byte
}
func (e ErrTimestampWitnessNotIndependent) Error() string {
    return fmt.Sprintf("evidence %x has non-independent timestamp witnesses", e.EvidenceID[:8])
}

type ErrCannotSelectWitnesses struct {
    Cause error
}
func (e ErrCannotSelectWitnesses) Error() string {
    return fmt.Sprintf("cannot select timestamp witnesses: %v", e.Cause)
}
```

// EvidenceAnalysis contains structured analysis of all evidence
type EvidenceAnalysis struct {
    AnalysisID      [32]byte
    DisputeID       [32]byte

    // Claim Analysis
    ClaimsExtracted []Claim            // All claims from both parties
    ClaimValidity   map[[16]byte]ClaimValidity // Validity of each claim

    // Evidence Evaluation
    EvidenceScoring map[[32]byte]EvidenceScore // Score for each evidence item
    ObjectiveFindings map[string]interface{}   // Objective measurements

    // Contract Analysis
    ContractTerms   map[string]interface{} // Relevant contract terms
    TermsViolated   []string           // Identified violations

    // Reasoning
    ProviderArguments []string         // Provider's key arguments
    ConsumerArguments []string         // Consumer's key arguments
    KeyFactors       []FactorAnalysis  // Factors influencing decision

    // Confidence
    OverallConfidence float64          // Confidence in analysis (0.0-1.0)
    AnalyzedAt       time.Time
    AnalyzedBy       [32]byte          // Arbitrator who performed analysis
}

// ClaimValidity assesses the validity of a claim
type ClaimValidity struct {
    ClaimID         [16]byte
    IsValid         bool
    SupportLevel    float64            // 0.0-1.0 how well supported
    Reasoning       string
    SupportingEvidence [][32]byte
    ContraEvidence  [][32]byte
}

// EvidenceScore evaluates individual evidence items
type EvidenceScore struct {
    EvidenceID      [32]byte
    Relevance       float64            // 0.0-1.0 relevance to dispute
    Reliability     float64            // 0.0-1.0 reliability of source
    Weight          float64            // 0.0-1.0 overall weight
    Notes           string
}

// FactorAnalysis examines decision factors
type FactorAnalysis struct {
    FactorName      string
    FactorType      FactorType
    Impact          float64            // -1.0 to 1.0 (negative favors consumer, positive favors provider)
    Confidence      float64            // 0.0-1.0
    Explanation     string
    SupportingData  map[string]interface{}
}

// FactorType categorizes decision factors
type FactorType uint8

const (
    FactorTypeObjective    FactorType = 1  // Objectively measurable (SLA metrics)
    FactorTypeSubjective   FactorType = 2  // Subjective assessment (quality)
    FactorTypeContractual  FactorType = 3  // Contract term interpretation
    FactorTypePrecedent    FactorType = 4  // Based on prior cases
)

// RunArbitrationProcess executes the full AI arbitration workflow
func RunArbitrationProcess(
    contractID [32]byte,
    disputeID [32]byte,
    arbitrators []AIArbitratorAgent,
    config *AIArbitratorConfig,
) (*AIArbitrationProcess, error) {

    process := &AIArbitrationProcess{
        ProcessID:      generateProcessID(contractID, disputeID),
        ContractID:     contractID,
        DisputeID:      disputeID,
        Arbitrators:    arbitrators,
        QuorumRequired: config.QuorumRequired,
        StartedAt:      time.Now(),
        Stage:          StageEvidenceCollection,
        AuditLog:       make([]AuditEntry, 0),
    }

    // Stage 1: Evidence Collection
    evidence, err := CollectEvidence(disputeID, config.MaxEvidenceSize)
    if err != nil {
        return nil, ErrEvidenceCollectionFailed{Cause: err}
    }
    process.Evidence = evidence
    process.EvidenceHash = hashEvidence(evidence)
    process.Stage = StageAnalysis
    process.logAudit("evidence_collected", evidence)

    // Stage 2: Evidence Analysis
    analysis, err := AnalyzeEvidence(evidence, arbitrators[0])
    if err != nil {
        return nil, ErrAnalysisFailed{Cause: err}
    }
    process.Analysis = analysis
    process.Stage = StageDeliberation
    process.logAudit("analysis_completed", analysis)

    // Stage 3: Deliberation (each arbitrator votes)
    decisions := make([]ArbitratorVote, len(arbitrators))
    for i, arbitrator := range arbitrators {
        vote, err := arbitrator.RenderDecision(analysis, config)
        if err != nil {
            return nil, ErrDecisionFailed{
                ArbitratorID: arbitrator.ArbitratorID,
                Cause:        err,
            }
        }
        decisions[i] = *vote
        process.logAudit("vote_cast", vote)
    }
    process.Decisions = decisions
    process.Stage = StageDecision

    // Stage 4: Final Decision (tally votes)
    finalDecision, err := TallyAIArbitratorVotes(decisions, config.QuorumRequired)
    if err != nil {
        return nil, ErrTallyFailed{Cause: err}
    }
    process.FinalDecision = finalDecision

    // Check confidence threshold
    if finalDecision.Confidence < config.AutoAppealThreshold {
        process.Stage = StageAppeal
        process.logAudit("auto_appeal", "confidence below threshold")
        return process, ErrAutoAppealTriggered{
            Confidence: finalDecision.Confidence,
            Threshold:  config.AutoAppealThreshold,
        }
    }

    // Stage 5: Close process
    now := time.Now()
    process.CompletedAt = &now
    process.Stage = StageClosed
    process.logAudit("process_completed", finalDecision)

    // Generate signed transcript
    process.SignedTranscript = process.generateSignedTranscript()

    return process, nil
}

// logAudit adds an entry to the audit log
func (p *AIArbitrationProcess) logAudit(event string, data interface{}) {
    entry := AuditEntry{
        Timestamp: time.Now(),
        Event:     event,
        Data:      data,
    }
    p.AuditLog = append(p.AuditLog, entry)
}

// AuditEntry records process events
type AuditEntry struct {
    Timestamp time.Time
    Event     string
    Data      interface{}
}
```

**REST Endpoint:**
```
POST /disputes/{disputeID}/ai-arbitration
```

**Request:**
```json
{
  "arbitrators": ["0xabcd...", "0xdef0...", "0x1234..."],
  "config": {
    "quorumRequired": 2,
    "confidenceThreshold": 0.80,
    "autoAppealThreshold": 0.70
  }
}
```

**Response (200 OK):**
```json
{
  "processID": "0x5678...",
  "stage": "decision",
  "finalDecision": {
    "outcome": "provider_wins",
    "confidence": 0.87,
    "reasoning": {...}
  },
  "completedAt": "2026-01-09T12:30:00Z"
}
```

**Error Response (202 Accepted - Auto Appeal):**
```json
{
  "processID": "0x5678...",
  "stage": "appeal",
  "reason": "confidence_below_threshold",
  "decision": {
    "outcome": "consumer_wins",
    "confidence": 0.65
  },
  "appealTo": "human_arbitrators",
  "appealDeadline": "2026-01-12T12:30:00Z"
}
```

### 5. AIArbitrationDecision Structure

```go
// AIArbitrationDecision represents the final decision from AI arbitration
type AIArbitrationDecision struct {
    DecisionID      [32]byte
    DisputeID       [32]byte
    ProcessID       [32]byte

    // Decision
    Outcome         DisputeOutcome     // Provider wins, consumer wins, or split
    SplitRatio      float64            // If split: ratio to provider (0.0-1.0)

    // Reasoning (Structured)
    Reasoning       *StructuredReasoning

    // Confidence Assessment
    Confidence      float64            // Overall confidence (0.0-1.0)
    ConfidenceFactors map[string]float64 // Confidence per factor

    // Arbitrator Votes
    VotingArbitrators [][32]byte       // Arbitrators who voted
    ConsensusLevel    float64          // Agreement level (0.0-1.0)

    // Evidence References
    KeyEvidence     [][32]byte         // Evidence that was decisive
    DisputedEvidence [][32]byte        // Evidence that was contested

    // Appeal Recommendation
    RecommendAppeal bool               // Whether to appeal to human
    AppealReason    string             // Why appeal is recommended

    // Timing
    RenderedAt      time.Time
    ProcessingTime  time.Duration

    // Signatures
    ArbitratorSignatures [][]byte      // Each arbitrator's signature
    AggregateSignature   []byte        // FROST threshold signature
}

// StructuredReasoning provides detailed reasoning for the decision
type StructuredReasoning struct {
    // Summary
    ExecutiveSummary string             // Brief summary of decision

    // Findings
    FactFindings    []FactFinding      // Factual findings
    LegalFindings   []LegalFinding     // Contract interpretation

    // Analysis
    ProviderPosition PositionAnalysis   // Provider's position analysis
    ConsumerPosition PositionAnalysis   // Consumer's position analysis

    // Decision Rationale
    DecisionFactors []FactorAnalysis   // Factors that led to decision
    WeightedScores  map[string]float64 // Numerical scoring

    // Explanations
    WhyProviderWins []string           // Reasons provider prevailed (if applicable)
    WhyConsumerWins []string           // Reasons consumer prevailed (if applicable)

    // Precedents
    SimilarCases    [][32]byte         // Similar past disputes
    Consistency     float64            // Consistency with precedents
}

// FactFinding represents a factual determination
type FactFinding struct {
    FindingID       [16]byte
    Description     string
    SupportingEvidence [][32]byte
    Confidence      float64            // 0.0-1.0
    Disputed        bool               // Whether finding is disputed
}

// LegalFinding represents contract term interpretation
type LegalFinding struct {
    FindingID       [16]byte
    ContractClause  string             // Relevant contract clause
    Interpretation  string             // How clause is interpreted
    AppliesTo       string             // Provider or Consumer
    Impact          string             // How this affects the outcome
}

// PositionAnalysis evaluates a party's overall position
type PositionAnalysis struct {
    PartyID         [32]byte
    OverallStrength float64            // 0.0-1.0
    StrongPoints    []string
    WeakPoints      []string
    EvidenceQuality float64            // 0.0-1.0
    LegalBasis      float64            // 0.0-1.0
}

// ArbitratorVote represents a single arbitrator's decision
type ArbitratorVote struct {
    ArbitratorID    [32]byte
    DecisionID      [32]byte

    Outcome         DisputeOutcome
    SplitRatio      float64
    Confidence      float64

    Reasoning       string             // Brief reasoning
    KeyFactors      []string           // Main factors in decision

    RenderedAt      time.Time
    ProcessingTime  time.Duration
    Signature       []byte             // Arbitrator's signature
}

// TallyAIArbitratorVotes aggregates multiple arbitrator decisions
func TallyAIArbitratorVotes(
    votes []ArbitratorVote,
    quorum uint8,
) (*AIArbitrationDecision, error) {

    if len(votes) < int(quorum) {
        return nil, ErrInsufficientVotes{
            Required: int(quorum),
            Received: len(votes),
        }
    }

    // Count outcomes
    outcomeCounts := make(map[DisputeOutcome]int)
    outcomeConfidences := make(map[DisputeOutcome][]float64)

    for _, vote := range votes {
        outcomeCounts[vote.Outcome]++
        outcomeConfidences[vote.Outcome] = append(
            outcomeConfidences[vote.Outcome],
            vote.Confidence,
        )
    }

    // Find majority outcome
    var majorityOutcome DisputeOutcome
    var majorityCount int
    for outcome, count := range outcomeCounts {
        if count > majorityCount {
            majorityOutcome = outcome
            majorityCount = count
        }
    }

    if majorityCount < int(quorum) {
        return nil, ErrNoQuorum{
            Required:  int(quorum),
            BestCount: majorityCount,
        }
    }

    // Calculate average confidence for majority outcome
    confidences := outcomeConfidences[majorityOutcome]
    avgConfidence := average(confidences)

    // Calculate consensus level
    consensusLevel := float64(majorityCount) / float64(len(votes))

    // Aggregate reasoning
    reasoning := aggregateReasoning(votes, majorityOutcome)

    decision := &AIArbitrationDecision{
        DecisionID:     generateDecisionID(),
        Outcome:        majorityOutcome,
        Reasoning:      reasoning,
        Confidence:     avgConfidence,
        ConsensusLevel: consensusLevel,
        RenderedAt:     time.Now(),
    }

    // Determine if appeal should be recommended
    if avgConfidence < 0.80 || consensusLevel < 0.75 {
        decision.RecommendAppeal = true
        decision.AppealReason = fmt.Sprintf(
            "Low confidence (%.2f) or consensus (%.2f)",
            avgConfidence, consensusLevel,
        )
    }

    return decision, nil
}

// aggregateReasoning combines reasoning from multiple arbitrators
func aggregateReasoning(votes []ArbitratorVote, outcome DisputeOutcome) *StructuredReasoning {
    reasoning := &StructuredReasoning{
        DecisionFactors: make([]FactorAnalysis, 0),
        WeightedScores:  make(map[string]float64),
    }

    // Collect all factors from votes with matching outcome
    for _, vote := range votes {
        if vote.Outcome == outcome {
            for _, factor := range vote.KeyFactors {
                reasoning.DecisionFactors = append(reasoning.DecisionFactors, FactorAnalysis{
                    FactorName:  factor,
                    Confidence:  vote.Confidence,
                    Explanation: vote.Reasoning,
                })
            }
        }
    }

    return reasoning
}

// average calculates average of float64 slice
func average(values []float64) float64 {
    if len(values) == 0 {
        return 0.0
    }
    sum := 0.0
    for _, v := range values {
        sum += v
    }
    return sum / float64(len(values))
}

// =============================================================================
// DECISION ENFORCEMENT (P4-C13) + EXECUTION STATE MACHINE (P5-C4)
// =============================================================================
// CRITICAL: Without this function, decisions are rendered but NEVER executed.
// This leads to funds being stuck in escrow indefinitely.
//
// SECURITY FIX (P5-C4): Added execution state machine with:
// 1. Persistent state tracking: Rendered→ExecutionPending→Executing→Complete
// 2. 24-hour execution timeout with automatic retry
// 3. Partial execution recovery for multi-party transfers
//
// EXECUTION STATE MACHINE DIAGRAM:
//
// ```
//                                  Appeal Filed
//     ┌──────────────┐            (pause execution)
//     │  StateRendered│◄─────────────────────────────────┐
//     │  (Decision    │                                   │
//     │   complete)   │                                   │
//     └──────┬───────┘                                   │
//            │ Appeal window expires                     │
//            │ (72h default)                             │
//            ▼                                           │
//     ┌──────────────────┐                               │
//     │ StateExecution   │                               │
//     │ Pending          │                               │
//     │ (Ready to exec)  │                               │
//     └──────┬───────────┘                               │
//            │ Begin execution                           │
//            ▼                                           │
//     ┌──────────────────┐                               │
//     │ StateExecuting   │◄──────────────────┐           │
//     │ (In progress)    │                   │           │
//     └──────┬───────────┘                   │           │
//            │                               │           │
//     ┌──────┼──────────────────────┐        │           │
//     │      │                      │        │           │
//     ▼      ▼                      ▼        │           │
// ┌────────┐ ┌─────────────┐ ┌────────────┐  │           │
// │Complete│ │PartialFail │ │ Failed     │  │           │
// │        │ │ (retry)    │─┘ (max retry)│  │           │
// └────────┘ └─────────────┘  └───────────┘  │           │
//                                            │           │
//     Retry with exponential backoff:        │           │
//       Retry 1: Wait 1 minute  ─────────────┘           │
//       Retry 2: Wait 2 minutes ─────────────┘           │
//       Retry 3: Wait 3 minutes ─────────────┘           │
//                                                        │
//     24-hour execution timeout applies                  │
//     from first execution attempt                       │
// ```
//
// KEY EXECUTION PARAMETERS:
// - Execution Timeout: 24 hours from first attempt
// - Max Retries: 3
// - Retry Backoff: 1min → 2min → 3min (exponential)
// - Escrow release included within execution

// ExecutionState tracks the current state of decision enforcement
type ExecutionState uint8

const (
    ExecutionStateRendered        ExecutionState = iota // Decision made, waiting for appeal window
    ExecutionStatePending                               // Appeal window passed, ready to execute
    ExecutionStateExecuting                             // Execution in progress
    ExecutionStatePartialFailure                        // Some transfers succeeded, some failed
    ExecutionStateComplete                              // All transfers completed
    ExecutionStateFailed                                // Execution failed after all retries
)

// ExecutionRecord tracks the state machine for a decision's execution
// SECURITY FIX (P5-C4): This is persisted to database for recovery after crashes
type ExecutionRecord struct {
    DecisionID       [32]byte
    ContractID       [32]byte
    CurrentState     ExecutionState
    StateChangedAt   time.Time
    ExecutionTimeout time.Time      // 24h from first execution attempt

    // Partial execution tracking - enables recovery
    EscrowLocked     bool           // Escrow lock acquired
    ProviderPaid     bool           // Provider payment completed
    ConsumerRefunded bool           // Consumer refund completed (if applicable)
    PlatformFeePaid  bool           // Platform fee deducted
    RecordsStored    bool           // DHT records updated

    // Amounts for recovery verification
    ProviderAmount   uint64
    ConsumerAmount   uint64
    PlatformFee      uint64

    // Error tracking
    LastError        string
    RetryCount       int
    NextRetryAt      time.Time
}

// ExecutionStateMachine manages decision execution with recovery
// CRITICAL (P5-C4): All state transitions are persisted BEFORE execution
type ExecutionStateMachine struct {
    db               *Database
    escrowService    *EscrowService
    config           *DecisionEnforcementConfig
    executionTimeout time.Duration  // Default: 24h
}

// TransitionTo changes the execution state atomically
func (sm *ExecutionStateMachine) TransitionTo(
    record *ExecutionRecord,
    newState ExecutionState,
) error {
    // Validate transition is allowed
    if !isValidTransition(record.CurrentState, newState) {
        return ErrInvalidStateTransition{
            From: record.CurrentState,
            To:   newState,
        }
    }

    // Persist state change BEFORE any execution
    oldState := record.CurrentState
    record.CurrentState = newState
    record.StateChangedAt = time.Now()

    if err := sm.db.SaveExecutionRecord(record); err != nil {
        // Rollback on persistence failure
        record.CurrentState = oldState
        return fmt.Errorf("state transition persistence failed: %w", err)
    }

    return nil
}

// isValidTransition checks if state transition is allowed
func isValidTransition(from, to ExecutionState) bool {
    transitions := map[ExecutionState][]ExecutionState{
        ExecutionStateRendered:       {ExecutionStatePending},
        ExecutionStatePending:        {ExecutionStateExecuting},
        ExecutionStateExecuting:      {ExecutionStateComplete, ExecutionStatePartialFailure, ExecutionStateFailed},
        ExecutionStatePartialFailure: {ExecutionStateExecuting, ExecutionStateComplete, ExecutionStateFailed},
        ExecutionStateFailed:         {ExecutionStateExecuting}, // Manual retry allowed
    }
    allowed, ok := transitions[from]
    if !ok {
        return false
    }
    for _, valid := range allowed {
        if valid == to {
            return true
        }
    }
    return false
}

// RecoverPartialExecution resumes execution from partial failure
// SECURITY FIX (P5-C4): Handles crash recovery during multi-party transfer
func (sm *ExecutionStateMachine) RecoverPartialExecution(
    record *ExecutionRecord,
    decision *AIArbitrationDecision,
    contract *ServiceContract,
) (*DecisionEnforcementResult, error) {

    // Check execution timeout
    if time.Now().After(record.ExecutionTimeout) {
        if err := sm.TransitionTo(record, ExecutionStateFailed); err != nil {
            return nil, err
        }
        return nil, ErrExecutionTimeout{
            DecisionID: record.DecisionID,
            Timeout:    sm.executionTimeout,
        }
    }

    // Transition to Executing
    if err := sm.TransitionTo(record, ExecutionStateExecuting); err != nil {
        return nil, err
    }

    result := &DecisionEnforcementResult{
        DecisionID:     record.DecisionID,
        ContractID:     record.ContractID,
        ProviderAmount: record.ProviderAmount,
        ConsumerAmount: record.ConsumerAmount,
        PlatformFee:    record.PlatformFee,
    }

    // Resume from wherever we left off
    var lastErr error

    // Step 1: Ensure escrow is locked (idempotent)
    if !record.EscrowLocked {
        if err := sm.escrowService.EnsureLocked(record.ContractID, record.DecisionID); err != nil {
            lastErr = err
            goto handleError
        }
        record.EscrowLocked = true
        sm.db.SaveExecutionRecord(record)
    }

    // Step 2: Pay provider (idempotent via transaction ID)
    if !record.ProviderPaid && record.ProviderAmount > 0 {
        txID := generateTxID(record.DecisionID, "provider")
        if err := sm.escrowService.PayProvider(record.ContractID, record.ProviderAmount, txID); err != nil {
            lastErr = err
            goto handleError
        }
        record.ProviderPaid = true
        sm.db.SaveExecutionRecord(record)
    }

    // Step 3: Refund consumer (idempotent via transaction ID)
    if !record.ConsumerRefunded && record.ConsumerAmount > 0 {
        txID := generateTxID(record.DecisionID, "consumer")
        if err := sm.escrowService.RefundConsumer(record.ContractID, record.ConsumerAmount, txID); err != nil {
            lastErr = err
            goto handleError
        }
        record.ConsumerRefunded = true
        sm.db.SaveExecutionRecord(record)
    }

    // Step 4: Deduct platform fee (idempotent via transaction ID)
    if !record.PlatformFeePaid && record.PlatformFee > 0 {
        txID := generateTxID(record.DecisionID, "platform")
        if err := sm.escrowService.DeductPlatformFee(record.ContractID, record.PlatformFee, txID); err != nil {
            lastErr = err
            goto handleError
        }
        record.PlatformFeePaid = true
        sm.db.SaveExecutionRecord(record)
    }

    // Step 5: Store DHT records (idempotent)
    if !record.RecordsStored {
        storeEnforcementRecord(result)
        record.RecordsStored = true
        sm.db.SaveExecutionRecord(record)
    }

    // All steps complete
    if err := sm.TransitionTo(record, ExecutionStateComplete); err != nil {
        return nil, err
    }
    result.Executed = true
    result.ExecutedAt = time.Now()
    result.EscrowReleased = true
    return result, nil

handleError:
    record.LastError = lastErr.Error()
    record.RetryCount++
    record.NextRetryAt = time.Now().Add(sm.config.RetryBackoff * time.Duration(record.RetryCount))
    sm.TransitionTo(record, ExecutionStatePartialFailure)
    sm.db.SaveExecutionRecord(record)
    return nil, lastErr
}

// generateTxID creates idempotent transaction ID for each operation
func generateTxID(decisionID [32]byte, operation string) [32]byte {
    h := sha256.New()
    h.Write(decisionID[:])
    h.Write([]byte(operation))
    var txID [32]byte
    copy(txID[:], h.Sum(nil))
    return txID
}

type ErrInvalidStateTransition struct {
    From ExecutionState
    To   ExecutionState
}

func (e ErrInvalidStateTransition) Error() string {
    return fmt.Sprintf("invalid state transition from %d to %d", e.From, e.To)
}

type ErrExecutionTimeout struct {
    DecisionID [32]byte
    Timeout    time.Duration
}

func (e ErrExecutionTimeout) Error() string {
    return fmt.Sprintf("execution timeout for decision %x after %v", e.DecisionID[:8], e.Timeout)
}

// DecisionEnforcementConfig configures the enforcement system
type DecisionEnforcementConfig struct {
    AppealWindowDuration  time.Duration // Wait period before enforcement (default: 72h)
    AutoEnforceOnExpiry   bool          // Auto-enforce after appeal window (default: true)
    RequireConfirmation   bool          // Require winning party confirmation (default: false)

    // Execution Timeout
    ExecutionTimeout      time.Duration // Maximum time allowed for execution (default: 24h)

    // Retry Policy with Exponential Backoff
    MaxRetries            int           // Max retries for failed escrow operations (default: 3)
    RetryBackoffSchedule  []time.Duration // Backoff intervals: [1m, 2m, 3m] for retries 1, 2, 3
}

// DefaultDecisionEnforcementConfig provides production-ready defaults
var DefaultDecisionEnforcementConfig = DecisionEnforcementConfig{
    AppealWindowDuration:  72 * time.Hour,
    AutoEnforceOnExpiry:   true,
    RequireConfirmation:   false,
    ExecutionTimeout:      24 * time.Hour,
    MaxRetries:            3,
    RetryBackoffSchedule:  []time.Duration{
        1 * time.Minute,   // First retry after 1 minute
        2 * time.Minute,   // Second retry after 2 minutes
        3 * time.Minute,   // Third retry after 3 minutes (final)
    },
}

// GetRetryBackoff returns the backoff duration for a given retry attempt
func (c *DecisionEnforcementConfig) GetRetryBackoff(attempt int) time.Duration {
    if attempt < 0 || attempt >= len(c.RetryBackoffSchedule) {
        // Default to last interval if out of range
        if len(c.RetryBackoffSchedule) > 0 {
            return c.RetryBackoffSchedule[len(c.RetryBackoffSchedule)-1]
        }
        return 1 * time.Minute
    }
    return c.RetryBackoffSchedule[attempt]
}

// DecisionEnforcementResult records the outcome of decision enforcement
type DecisionEnforcementResult struct {
    DecisionID       [32]byte
    DisputeID        [32]byte
    ContractID       [32]byte

    // Execution Status
    Executed         bool
    ExecutedAt       time.Time
    ExecutedBy       [32]byte    // Node that performed execution

    // Escrow Operations
    EscrowReleased   bool
    ProviderAmount   uint64      // Amount released to provider
    ConsumerAmount   uint64      // Amount returned to consumer (if split/consumer wins)
    PlatformFee      uint64      // Platform fee deducted

    // Transaction References
    EscrowTxHash     [32]byte    // Transaction hash for escrow release
    ProviderTxHash   [32]byte    // Provider payment transaction
    ConsumerTxHash   [32]byte    // Consumer refund transaction (if applicable)

    // Verification
    VerifiedByTPM    bool        // TPM attestation of enforcement
    TPMQuote         []byte      // TPM quote proving enforcement

    // Errors
    Error            string      // Error message if failed
    RetryCount       int         // Number of retries attempted
}

// ExecuteAIArbitrationDecision enforces an AI arbitration decision by releasing escrow
// This is the CRITICAL function that connects decisions to actual fund movements
func ExecuteAIArbitrationDecision(
    decision *AIArbitrationDecision,
    contract *ServiceContract,
    config *DecisionEnforcementConfig,
) (*DecisionEnforcementResult, error) {

    result := &DecisionEnforcementResult{
        DecisionID: decision.DecisionID,
        DisputeID:  decision.DisputeID,
        ContractID: contract.ContractID,
    }

    // Step 1: Verify decision is final (appeal window passed or no appeal filed)
    if !isDecisionFinal(decision, config) {
        return nil, ErrDecisionNotFinal{
            DecisionID:     decision.DecisionID,
            AppealDeadline: decision.RenderedAt.Add(config.AppealWindowDuration),
        }
    }

    // Step 2: Verify we have authority to execute (node is authorized executor)
    executorAuth, err := verifyExecutorAuthority(decision, contract)
    if err != nil {
        return nil, ErrUnauthorizedExecutor{Cause: err}
    }
    result.ExecutedBy = executorAuth.NodeID

    // Step 3: Lock escrow for execution (atomic operation)
    escrowLock, err := acquireEscrowLock(contract.ContractID, decision.DecisionID)
    if err != nil {
        return nil, ErrEscrowLockFailed{Cause: err}
    }
    defer releaseEscrowLock(escrowLock)

    // Step 4: Verify escrow state matches expected
    escrow, err := getEscrowState(contract.ContractID)
    if err != nil {
        return nil, ErrEscrowStateFailed{Cause: err}
    }
    if escrow.Status != EscrowStatusHeld {
        return nil, ErrEscrowNotHeld{
            ContractID: contract.ContractID,
            Status:     escrow.Status,
        }
    }

    // Step 5: Calculate distribution based on decision outcome
    distribution := calculateDistribution(decision, escrow, contract)
    result.ProviderAmount = distribution.ProviderAmount
    result.ConsumerAmount = distribution.ConsumerAmount
    result.PlatformFee = distribution.PlatformFee

    // Step 6: Execute escrow release with retry logic
    var lastErr error
    for attempt := 0; attempt <= config.MaxRetries; attempt++ {
        result.RetryCount = attempt

        // Create TPM-attested release request
        releaseReq := &EscrowReleaseRequest{
            ContractID:     contract.ContractID,
            DecisionID:     decision.DecisionID,
            Distribution:   distribution,
            RequestedAt:    time.Now(),
            RequestedBy:    executorAuth.NodeID,
        }

        // Sign release request with TPM
        if err := signWithTPM(releaseReq); err != nil {
            lastErr = err
            time.Sleep(config.RetryBackoff * time.Duration(attempt+1))
            continue
        }

        // Execute escrow release
        releaseResult, err := executeEscrowRelease(releaseReq)
        if err != nil {
            lastErr = err
            time.Sleep(config.RetryBackoff * time.Duration(attempt+1))
            continue
        }

        // Success - populate result
        result.Executed = true
        result.ExecutedAt = time.Now()
        result.EscrowReleased = true
        result.EscrowTxHash = releaseResult.TransactionHash
        result.ProviderTxHash = releaseResult.ProviderTxHash
        result.ConsumerTxHash = releaseResult.ConsumerTxHash
        result.VerifiedByTPM = true
        result.TPMQuote = releaseResult.TPMQuote
        lastErr = nil
        break
    }

    if lastErr != nil {
        result.Executed = false
        result.Error = lastErr.Error()
        return result, ErrEnforcementFailed{
            DecisionID: decision.DecisionID,
            Cause:      lastErr,
            Attempts:   config.MaxRetries + 1,
        }
    }

    // Step 7: Store enforcement record in DHT for audit
    storeEnforcementRecord(result)

    // Step 8: Update contract status
    updateContractStatus(contract.ContractID, ContractStatusResolved)

    // Step 9: Emit enforcement event
    emitEnforcementEvent(result)

    return result, nil
}

// isDecisionFinal checks if the appeal window has passed
func isDecisionFinal(decision *AIArbitrationDecision, config *DecisionEnforcementConfig) bool {
    appealDeadline := decision.RenderedAt.Add(config.AppealWindowDuration)

    // Check if appeal was filed
    appeal, err := getAppealForDecision(decision.DecisionID)
    if err == nil && appeal != nil {
        // Appeal exists - decision is NOT final until appeal resolved
        return appeal.Status == AppealStatusResolved
    }

    // No appeal - check if window has passed
    return time.Now().After(appealDeadline)
}

// calculateDistribution determines how escrow should be split
func calculateDistribution(
    decision *AIArbitrationDecision,
    escrow *EscrowState,
    contract *ServiceContract,
) *EscrowDistribution {

    totalAmount := escrow.Amount
    platformFee := uint64(float64(totalAmount) * contract.EscrowConfig.PlatformFeePercent)
    distributableAmount := totalAmount - platformFee

    switch decision.Outcome {
    case DisputeOutcomeProviderWins:
        return &EscrowDistribution{
            ProviderAmount: distributableAmount,
            ConsumerAmount: 0,
            PlatformFee:    platformFee,
        }

    case DisputeOutcomeConsumerWins:
        return &EscrowDistribution{
            ProviderAmount: 0,
            ConsumerAmount: distributableAmount,
            PlatformFee:    platformFee,
        }

    case DisputeOutcomeSplit:
        providerShare := uint64(float64(distributableAmount) * decision.SplitRatio)
        consumerShare := distributableAmount - providerShare
        return &EscrowDistribution{
            ProviderAmount: providerShare,
            ConsumerAmount: consumerShare,
            PlatformFee:    platformFee,
        }

    default:
        // Fallback: 50/50 split
        halfAmount := distributableAmount / 2
        return &EscrowDistribution{
            ProviderAmount: halfAmount,
            ConsumerAmount: distributableAmount - halfAmount,
            PlatformFee:    platformFee,
        }
    }
}

// EscrowDistribution specifies how escrow funds are distributed
type EscrowDistribution struct {
    ProviderAmount uint64
    ConsumerAmount uint64
    PlatformFee    uint64
}

// EscrowReleaseRequest is a TPM-signed request to release escrow
type EscrowReleaseRequest struct {
    ContractID   [32]byte
    DecisionID   [32]byte
    Distribution *EscrowDistribution
    RequestedAt  time.Time
    RequestedBy  [32]byte
    Signature    []byte  // TPM signature over request
}

// Error types for decision enforcement
type ErrDecisionNotFinal struct {
    DecisionID     [32]byte
    AppealDeadline time.Time
}
func (e ErrDecisionNotFinal) Error() string {
    return fmt.Sprintf("decision %x not final until %s",
        e.DecisionID[:8], e.AppealDeadline.Format(time.RFC3339))
}

type ErrUnauthorizedExecutor struct {
    Cause error
}
func (e ErrUnauthorizedExecutor) Error() string {
    return fmt.Sprintf("unauthorized executor: %v", e.Cause)
}

type ErrEscrowLockFailed struct {
    Cause error
}
func (e ErrEscrowLockFailed) Error() string {
    return fmt.Sprintf("failed to acquire escrow lock: %v", e.Cause)
}

type ErrEscrowStateFailed struct {
    Cause error
}
func (e ErrEscrowStateFailed) Error() string {
    return fmt.Sprintf("failed to get escrow state: %v", e.Cause)
}

type ErrEscrowNotHeld struct {
    ContractID [32]byte
    Status     EscrowStatus
}
func (e ErrEscrowNotHeld) Error() string {
    return fmt.Sprintf("escrow for contract %x is not held (status: %d)",
        e.ContractID[:8], e.Status)
}

type ErrEnforcementFailed struct {
    DecisionID [32]byte
    Cause      error
    Attempts   int
}
func (e ErrEnforcementFailed) Error() string {
    return fmt.Sprintf("enforcement failed for decision %x after %d attempts: %v",
        e.DecisionID[:8], e.Attempts, e.Cause)
}

// EnforcementScheduler automatically enforces decisions after appeal window
type EnforcementScheduler struct {
    config          *DecisionEnforcementConfig
    pendingDecisions map[[32]byte]time.Time // DecisionID -> enforcement deadline
    mu              sync.RWMutex
}

// ScheduleEnforcement adds a decision to the enforcement queue
func (es *EnforcementScheduler) ScheduleEnforcement(decision *AIArbitrationDecision) {
    es.mu.Lock()
    defer es.mu.Unlock()

    enforcementDeadline := decision.RenderedAt.Add(es.config.AppealWindowDuration)
    es.pendingDecisions[decision.DecisionID] = enforcementDeadline
}

// RunEnforcementLoop continuously checks for decisions ready to enforce
func (es *EnforcementScheduler) RunEnforcementLoop(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            es.processReadyDecisions()
        }
    }
}

// processReadyDecisions enforces all decisions past their appeal window
func (es *EnforcementScheduler) processReadyDecisions() {
    es.mu.Lock()
    readyDecisions := make([][32]byte, 0)
    now := time.Now()

    for decisionID, deadline := range es.pendingDecisions {
        if now.After(deadline) {
            readyDecisions = append(readyDecisions, decisionID)
        }
    }

    // Remove from pending before releasing lock
    for _, decisionID := range readyDecisions {
        delete(es.pendingDecisions, decisionID)
    }
    es.mu.Unlock()

    // Enforce each ready decision
    for _, decisionID := range readyDecisions {
        go es.enforceDecision(decisionID)
    }
}

// enforceDecision retrieves and enforces a single decision
func (es *EnforcementScheduler) enforceDecision(decisionID [32]byte) {
    decision, err := getDecisionFromDHT(decisionID)
    if err != nil {
        logEnforcementError(decisionID, err)
        return
    }

    contract, err := getContractFromDHT(decision.ContractID)
    if err != nil {
        logEnforcementError(decisionID, err)
        return
    }

    result, err := ExecuteAIArbitrationDecision(decision, contract, es.config)
    if err != nil {
        logEnforcementError(decisionID, err)
        // Re-schedule for retry if transient error
        if isTransientError(err) {
            es.ScheduleEnforcement(decision)
        }
        return
    }

    logEnforcementSuccess(result)
}
```

**REST Endpoint:**
```
GET /disputes/{disputeID}/decision
```

**Response (200 OK):**
```json
{
  "decisionID": "0x9abc...",
  "disputeID": "0x1234...",
  "outcome": "provider_wins",
  "splitRatio": 0.0,
  "confidence": 0.87,
  "consensusLevel": 1.0,
  "reasoning": {
    "executiveSummary": "Provider fully delivered the service as specified in the contract. Consumer's claims of incomplete delivery are not supported by objective evidence.",
    "factFindings": [
      {
        "description": "Service logs show 99.8% uptime, exceeding the 99.5% SLA",
        "confidence": 0.95,
        "supportingEvidence": ["0xlog1...", "0xlog2..."]
      },
      {
        "description": "Consumer confirmed receipt of deliverables on 2026-01-05",
        "confidence": 0.90,
        "supportingEvidence": ["0xtxn1..."]
      }
    ],
    "decisionFactors": [
      {
        "factorName": "SLA Compliance",
        "factorType": "objective",
        "impact": 0.8,
        "confidence": 0.95,
        "explanation": "Provider exceeded all SLA metrics"
      },
      {
        "factorName": "Evidence Quality",
        "factorType": "objective",
        "impact": 0.6,
        "confidence": 0.85,
        "explanation": "Provider submitted comprehensive logs and attestations"
      }
    ]
  },
  "recommendAppeal": false,
  "renderedAt": "2026-01-09T12:30:00Z",
  "processingTime": "4m32s"
}
```

### 6. Appeal Process from AI to Human

```go
// AppealRequest represents an appeal from AI to human arbitration
type AppealRequest struct {
    AppealID        [32]byte
    DisputeID       [32]byte
    OriginalDecisionID [32]byte

    // Appeal Basis
    AppealType      AppealType
    Reason          string             // Detailed reason for appeal
    NewEvidence     []EvidenceItem     // Additional evidence (if any)

    // Appellant
    AppellantID     [32]byte           // Party filing appeal
    AppealFee       uint64             // Fee paid for appeal

    // Original Decision Context
    OriginalDecision *AIArbitrationDecision
    ProcessTranscript []byte           // Signed transcript from AI process

    // Appeal Configuration
    RequestHumanCount uint8            // Number of human arbiters requested
    ExpeditedReview   bool             // Request expedited review

    // Timing
    FiledAt         time.Time
    Deadline        time.Time          // Deadline for human decision

    // Status
    Status          AppealStatus
    HumanDecision   *DisputeResolution // Final human decision
    CompletedAt     *time.Time
}

// AppealType categorizes the basis for appeal
type AppealType uint8

const (
    AppealTypeLowConfidence    AppealType = 1 // AI confidence too low (automatic)
    AppealTypeDisagreement     AppealType = 2 // Appellant disagrees with decision
    AppealTypeNewEvidence      AppealType = 3 // New evidence discovered
    AppealTypeProcessError     AppealType = 4 // Error in AI process
    AppealTypeBiasAllegation   AppealType = 5 // Alleged bias in AI decision
)

// AppealStatus tracks appeal state
type AppealStatus uint8

const (
    AppealStatusPending   AppealStatus = 1 // Appeal filed, awaiting review
    AppealStatusReviewing AppealStatus = 2 // Under human review
    AppealStatusUpheld    AppealStatus = 3 // Original decision upheld
    AppealStatusOverturned AppealStatus = 4 // Original decision overturned
    AppealStatusRemanded  AppealStatus = 5 // Sent back for re-arbitration
)

// AppealConfig defines appeal parameters
type AppealConfig struct {
    AllowAppeal         bool              // Whether appeals are allowed
    AppealWindow        time.Duration     // Window to file appeal (72h default)
    AppealFee           uint64            // Fee to file appeal
    AutoAppealOnLowConf bool              // Automatic appeal if confidence low
    ConfidenceThreshold float64           // Threshold for auto-appeal

    // Human Arbitrator Selection
    HumanArbiterCount   uint8             // Number of human arbiters (5 default)
    HumanQuorum         uint8             // Votes needed (3 default)

    // Review Process
    ExpeditedAvailable  bool              // Allow expedited review
    ExpeditedFee        uint64            // Additional fee for expedited
    StandardReviewTime  time.Duration     // Standard review timeframe
    ExpeditedReviewTime time.Duration     // Expedited review timeframe
}

// DefaultAppealConfig provides sensible defaults
var DefaultAppealConfig = AppealConfig{
    AllowAppeal:         true,
    AppealWindow:        72 * time.Hour,
    AppealFee:           100,  // tokens
    AutoAppealOnLowConf: true,
    ConfidenceThreshold: 0.70,
    HumanArbiterCount:   5,
    HumanQuorum:         3,
    ExpeditedAvailable:  true,
    ExpeditedFee:        500,  // tokens
    StandardReviewTime:  7 * 24 * time.Hour,   // 7 days
    ExpeditedReviewTime: 48 * time.Hour,        // 48 hours
}

### Appeal Fee Economics Fix (P4-M9)

**Problem**: Flat appeal fee (100 tokens) incentivizes frivolous appeals.
Appellants have nothing to lose if they lose - they just lose the 100 token fee.
This creates an incentive to file appeals to delay enforcement or harass opponents.

**Solution**: Implement loser-pays mechanism with escalating costs to discourage
frivolous appeals while preserving legitimate access to justice.

```go
// AppealFeeConfig defines the economic structure of appeals (P4-M9 Fix)
type AppealFeeConfig struct {
    // Base fees
    BaseFee           uint64   // Minimum filing fee (100 tokens)
    MaxFee            uint64   // Maximum fee cap (10000 tokens)

    // Loser-pays mechanism
    LoserPaysFraction float64  // Fraction of other party's costs loser pays (0.5 = 50%)
    LoserPaysCapMultiple float64 // Max loser-pays as multiple of base fee (5x = 500 tokens max)

    // Stake requirement (in addition to fee)
    StakeRequired     bool     // Whether stake is required
    StakeAmount       uint64   // Amount staked (returned if appeal succeeds)
    StakeForfeitOnLoss float64 // Fraction forfeited on loss (0.5 = 50%)

    // Escalating fees for repeat appellants
    RepeatAppealMultiplier float64 // Multiplier for subsequent appeals (1.5x)
    MaxRepeatMultiplier    float64 // Cap on repeat multiplier (3x)

    // Fee distribution
    WinnerRefundFraction float64 // Fraction of fee refunded to winner (0.8 = 80%)
    ArbiterReward        float64 // Fraction paid to arbiters (0.15 = 15%)
    NetworkFee           float64 // Fraction kept by network (0.05 = 5%)

    // Anti-gaming
    FrivolousAppealThreshold uint8 // Consecutive failed appeals before penalty (3)
    FrivolousAppealPenalty   float64 // Reputation penalty for frivolous appeals (0.05)
}

// DefaultAppealFeeConfig provides sensible defaults
var DefaultAppealFeeConfig = AppealFeeConfig{
    BaseFee:                  100,
    MaxFee:                   10000,
    LoserPaysFraction:        0.5,
    LoserPaysCapMultiple:     5.0,
    StakeRequired:            true,
    StakeAmount:              200,
    StakeForfeitOnLoss:       0.5,
    RepeatAppealMultiplier:   1.5,
    MaxRepeatMultiplier:      3.0,
    WinnerRefundFraction:     0.8,
    ArbiterReward:            0.15,
    NetworkFee:               0.05,
    FrivolousAppealThreshold: 3,
    FrivolousAppealPenalty:   0.05,
}

// AppealCostCalculator computes total appeal costs
type AppealCostCalculator struct {
    config      *AppealFeeConfig
    appealStats *AppealStats  // Track repeat appeals
}

// AppealStats tracks appeal history for a party
type AppealStats struct {
    NodeID              [32]byte
    TotalAppeals        uint32
    SuccessfulAppeals   uint32
    FailedAppeals       uint32
    ConsecutiveFailed   uint8    // For frivolous appeal detection
    TotalPaid           uint64   // Total appeal fees paid
    TotalRefunded       uint64   // Total fees refunded (from wins)
    LastAppealAt        time.Time
}

// CalculateTotalAppealCost computes total upfront cost to file appeal
func (c *AppealCostCalculator) CalculateTotalAppealCost(
    appellantID [32]byte,
    disputeValue uint64,
) (*AppealCostBreakdown, error) {

    stats, err := c.getAppealStats(appellantID)
    if err != nil {
        return nil, err
    }

    // Step 1: Calculate base fee with repeat multiplier
    baseFee := c.config.BaseFee
    if stats.TotalAppeals > 0 {
        multiplier := math.Pow(c.config.RepeatAppealMultiplier, float64(stats.ConsecutiveFailed))
        multiplier = math.Min(multiplier, c.config.MaxRepeatMultiplier)
        baseFee = uint64(float64(baseFee) * multiplier)
    }

    // Step 2: Cap fee at maximum
    baseFee = minUint64(baseFee, c.config.MaxFee)

    // Step 3: Calculate proportional stake (if required)
    stake := uint64(0)
    if c.config.StakeRequired {
        // Stake is proportional to dispute value but capped
        stake = c.config.StakeAmount
        if disputeValue > 1000 {
            // For high-value disputes, stake scales
            stake = uint64(float64(disputeValue) * 0.1) // 10% of dispute
            stake = minUint64(stake, c.config.MaxFee)
        }
    }

    // Step 4: Calculate maximum potential loss
    maxLoserPays := uint64(float64(baseFee) * c.config.LoserPaysCapMultiple)
    stakeLoss := uint64(float64(stake) * c.config.StakeForfeitOnLoss)
    maxPotentialLoss := baseFee + stakeLoss + maxLoserPays

    return &AppealCostBreakdown{
        BaseFee:           baseFee,
        Stake:             stake,
        TotalUpfront:      baseFee + stake,
        MaxLoserPays:      maxLoserPays,
        MaxPotentialLoss:  maxPotentialLoss,
        RepeatMultiplier:  float64(baseFee) / float64(c.config.BaseFee),
        WinsRequired:      c.calculateWinsRequired(stats),
    }, nil
}

// AppealCostBreakdown shows complete cost picture to appellant
type AppealCostBreakdown struct {
    BaseFee           uint64   // Filing fee
    Stake             uint64   // Stake (returned on win)
    TotalUpfront      uint64   // Total needed to file (fee + stake)
    MaxLoserPays      uint64   // Maximum additional cost if you lose
    MaxPotentialLoss  uint64   // Worst case total loss
    RepeatMultiplier  float64  // Current repeat appeal multiplier
    WinsRequired      uint8    // Wins needed to break even on fees
}

// ResolveAppealFinancials distributes funds after appeal decision
// SECURITY: This is called ONLY after appeal decision is final
func (c *AppealCostCalculator) ResolveAppealFinancials(
    appeal *AppealRequest,
    decision *DisputeResolution,
) (*AppealFinancialResolution, error) {

    resolution := &AppealFinancialResolution{
        AppealID:  appeal.AppealID,
        Winner:    decision.WinningParty,
        Loser:     decision.LosingParty,
        Decision:  decision.Outcome,
    }

    appellantWon := (decision.WinningParty == appeal.AppellantID)

    if appellantWon {
        // Appellant wins - refund most fees, return stake
        resolution.AppellantRefund = uint64(float64(appeal.AppealFee) * c.config.WinnerRefundFraction)
        resolution.AppellantStakeReturn = appeal.Stake // Full stake returned

        // Loser (other party) pays portion of appellant's costs
        loserPays := uint64(float64(appeal.AppealFee) * c.config.LoserPaysFraction)
        loserPays = minUint64(loserPays, uint64(float64(c.config.BaseFee)*c.config.LoserPaysCapMultiple))
        resolution.LoserOwes = loserPays

        // Update stats
        c.updateAppealStats(appeal.AppellantID, true)
    } else {
        // Appellant loses - forfeit portion of stake, may owe loser-pays
        resolution.AppellantRefund = 0 // No fee refund
        stakeForfeit := uint64(float64(appeal.Stake) * c.config.StakeForfeitOnLoss)
        resolution.AppellantStakeReturn = appeal.Stake - stakeForfeit

        // Appellant pays portion of other party's costs
        loserPays := uint64(float64(appeal.AppealFee) * c.config.LoserPaysFraction)
        loserPays = minUint64(loserPays, uint64(float64(c.config.BaseFee)*c.config.LoserPaysCapMultiple))
        resolution.LoserOwes = loserPays

        // Update stats and check for frivolous appeal
        c.updateAppealStats(appeal.AppellantID, false)
        if c.isFrivolousAppeal(appeal.AppellantID) {
            resolution.FrivolousAppealPenalty = c.config.FrivolousAppealPenalty
        }
    }

    // Distribute fees
    arbiterShare := uint64(float64(appeal.AppealFee) * c.config.ArbiterReward)
    networkShare := uint64(float64(appeal.AppealFee) * c.config.NetworkFee)

    resolution.ArbiterPayouts = c.distributeToArbiters(arbiterShare, appeal.ArbitersAssigned)
    resolution.NetworkFee = networkShare

    return resolution, nil
}

// AppealFinancialResolution represents final financial settlement
type AppealFinancialResolution struct {
    AppealID               [32]byte
    Winner                 [32]byte
    Loser                  [32]byte
    Decision               DisputeOutcome

    // Appellant financials
    AppellantRefund        uint64   // Fee refund (if won)
    AppellantStakeReturn   uint64   // Stake return (partial or full)

    // Loser pays
    LoserOwes              uint64   // Amount loser owes winner

    // Fee distribution
    ArbiterPayouts         map[[32]byte]uint64 // Per-arbiter payouts
    NetworkFee             uint64              // Network's share

    // Penalties
    FrivolousAppealPenalty float64  // Reputation penalty (if applicable)
}

// SECURITY FIX (P5-H7): Atomic multi-party transfer with rollback for appeal execution
// ExecuteAppealFinancialResolution atomically executes all appeal financial transfers
func ExecuteAppealFinancialResolution(
    ctx context.Context,
    resolution *AppealFinancialResolution,
    escrow *EscrowManager,
    txManager *TransactionManager,
) error {
    // Create atomic transaction batch
    txBatch := txManager.BeginAtomicBatch(ctx)
    defer txBatch.RollbackOnPanic()

    // Track executed transfers for rollback on failure
    executed := &AppealExecutionState{
        AppealID:    resolution.AppealID,
        StartedAt:   time.Now(),
        Transfers:   make([]ExecutedTransfer, 0),
    }

    // Phase 1: Lock escrow funds
    if err := escrow.LockForDistribution(resolution.AppealID); err != nil {
        return ErrAppealExecutionFailed{
            Phase: "lock_escrow",
            Cause: err,
        }
    }
    executed.EscrowLocked = true

    // Phase 2: Execute transfers in order with rollback tracking
    // Order matters: refunds before payouts to ensure sufficient funds

    // 2a: Return appellant stake
    if resolution.AppellantStakeReturn > 0 {
        transfer := &TransferRequest{
            From:    escrow.EscrowAccount(),
            To:      resolution.Winner, // Appellant (if they won) or original party
            Amount:  resolution.AppellantStakeReturn,
            Reason:  "appeal_stake_return",
        }
        if err := txBatch.AddTransfer(transfer); err != nil {
            return executeRollback(executed, escrow, txManager, err, "stake_return")
        }
        executed.Transfers = append(executed.Transfers, ExecutedTransfer{
            Type:   "stake_return",
            To:     transfer.To,
            Amount: transfer.Amount,
        })
    }

    // 2b: Appellant refund (if won)
    if resolution.AppellantRefund > 0 {
        transfer := &TransferRequest{
            From:    escrow.EscrowAccount(),
            To:      resolution.Winner,
            Amount:  resolution.AppellantRefund,
            Reason:  "appeal_fee_refund",
        }
        if err := txBatch.AddTransfer(transfer); err != nil {
            return executeRollback(executed, escrow, txManager, err, "fee_refund")
        }
        executed.Transfers = append(executed.Transfers, ExecutedTransfer{
            Type:   "fee_refund",
            To:     transfer.To,
            Amount: transfer.Amount,
        })
    }

    // 2c: Loser pays winner
    if resolution.LoserOwes > 0 {
        transfer := &TransferRequest{
            From:    resolution.Loser,
            To:      resolution.Winner,
            Amount:  resolution.LoserOwes,
            Reason:  "appeal_loser_pays",
        }
        if err := txBatch.AddTransfer(transfer); err != nil {
            return executeRollback(executed, escrow, txManager, err, "loser_pays")
        }
        executed.Transfers = append(executed.Transfers, ExecutedTransfer{
            Type:   "loser_pays",
            From:   transfer.From,
            To:     transfer.To,
            Amount: transfer.Amount,
        })
    }

    // 2d: Pay arbiters
    for arbiterID, payout := range resolution.ArbiterPayouts {
        if payout == 0 {
            continue
        }
        transfer := &TransferRequest{
            From:    escrow.EscrowAccount(),
            To:      arbiterID,
            Amount:  payout,
            Reason:  "appeal_arbiter_payout",
        }
        if err := txBatch.AddTransfer(transfer); err != nil {
            return executeRollback(executed, escrow, txManager, err, "arbiter_payout")
        }
        executed.Transfers = append(executed.Transfers, ExecutedTransfer{
            Type:   "arbiter_payout",
            To:     arbiterID,
            Amount: payout,
        })
    }

    // 2e: Network fee
    if resolution.NetworkFee > 0 {
        transfer := &TransferRequest{
            From:    escrow.EscrowAccount(),
            To:      NetworkFeeWallet,
            Amount:  resolution.NetworkFee,
            Reason:  "appeal_network_fee",
        }
        if err := txBatch.AddTransfer(transfer); err != nil {
            return executeRollback(executed, escrow, txManager, err, "network_fee")
        }
        executed.Transfers = append(executed.Transfers, ExecutedTransfer{
            Type:   "network_fee",
            Amount: transfer.Amount,
        })
    }

    // Phase 3: Commit all transfers atomically
    if err := txBatch.Commit(); err != nil {
        return executeRollback(executed, escrow, txManager, err, "commit")
    }

    // Phase 4: Mark escrow as distributed
    if err := escrow.MarkDistributed(resolution.AppealID); err != nil {
        // Transfers succeeded, but escrow state update failed
        // Log for manual reconciliation but don't fail the operation
        log.Error("escrow state update failed after successful distribution",
            "appealID", resolution.AppealID,
            "error", err)
    }

    executed.CompletedAt = time.Now()
    executed.Success = true

    // Store execution record for audit
    storeAppealExecutionRecord(executed)

    return nil
}

// executeRollback reverses executed transfers on failure
func executeRollback(
    executed *AppealExecutionState,
    escrow *EscrowManager,
    txManager *TransactionManager,
    originalErr error,
    failedPhase string,
) error {
    log.Warn("rolling back appeal financial execution",
        "appealID", executed.AppealID,
        "failedPhase", failedPhase,
        "transfersToRollback", len(executed.Transfers),
        "originalError", originalErr)

    // Rollback transfers in reverse order
    rollbackBatch := txManager.BeginAtomicBatch(context.Background())
    for i := len(executed.Transfers) - 1; i >= 0; i-- {
        transfer := executed.Transfers[i]
        reversal := &TransferRequest{
            From:    transfer.To,
            To:      transfer.From,
            Amount:  transfer.Amount,
            Reason:  "appeal_rollback",
        }
        if err := rollbackBatch.AddTransfer(reversal); err != nil {
            log.Error("failed to add rollback transfer",
                "transfer", transfer,
                "error", err)
            // Continue trying other rollbacks
        }
    }

    // Attempt to commit rollbacks
    if err := rollbackBatch.Commit(); err != nil {
        log.Error("rollback commit failed - manual intervention required",
            "appealID", executed.AppealID,
            "error", err)
        alertManualReconciliation(executed.AppealID, executed.Transfers, err)
    }

    // Release escrow lock
    if executed.EscrowLocked {
        escrow.UnlockEscrow(executed.AppealID)
    }

    return ErrAppealExecutionFailed{
        Phase:     failedPhase,
        Cause:     originalErr,
        Rollback:  true,
    }
}

// AppealExecutionState tracks execution progress for rollback
type AppealExecutionState struct {
    AppealID     [32]byte
    StartedAt    time.Time
    CompletedAt  time.Time
    Success      bool
    EscrowLocked bool
    Transfers    []ExecutedTransfer
}

// ExecutedTransfer records a completed transfer
type ExecutedTransfer struct {
    Type   string   // stake_return, fee_refund, loser_pays, arbiter_payout, network_fee
    From   [32]byte
    To     [32]byte
    Amount uint64
}

// ErrAppealExecutionFailed indicates appeal financial execution failed
type ErrAppealExecutionFailed struct {
    Phase    string
    Cause    error
    Rollback bool
}

func (e ErrAppealExecutionFailed) Error() string {
    if e.Rollback {
        return fmt.Sprintf("appeal execution failed at phase '%s' (rolled back): %v",
            e.Phase, e.Cause)
    }
    return fmt.Sprintf("appeal execution failed at phase '%s': %v", e.Phase, e.Cause)
}

// isFrivolousAppeal checks if appellant has pattern of frivolous appeals
func (c *AppealCostCalculator) isFrivolousAppeal(nodeID [32]byte) bool {
    stats, _ := c.getAppealStats(nodeID)
    return stats.ConsecutiveFailed >= c.config.FrivolousAppealThreshold
}

// calculateWinsRequired shows how many wins needed to break even
func (c *AppealCostCalculator) calculateWinsRequired(stats *AppealStats) uint8 {
    if stats.TotalPaid <= stats.TotalRefunded {
        return 0
    }
    deficit := stats.TotalPaid - stats.TotalRefunded
    avgRefund := uint64(float64(c.config.BaseFee) * c.config.WinnerRefundFraction)
    if avgRefund == 0 {
        return 255 // Max uint8 - can't break even
    }
    return uint8(math.Ceil(float64(deficit) / float64(avgRefund)))
}

// Helper functions
func minUint64(a, b uint64) uint64 {
    if a < b {
        return a
    }
    return b
}
```

### Appeal Economics Summary

| Scenario | Cost to Appellant | Outcome |
|----------|------------------|---------|
| Appeal & Win | Lose ~20% of fee, get stake back, other party pays 50% of your costs | Net positive |
| Appeal & Lose | Lose 100% of fee, lose 50% of stake, pay 50% of other party's costs | Net negative |
| Repeat Frivolous | Fee × 1.5-3x, reputation penalty after 3 consecutive fails | Strongly negative |

This creates strong economic incentive to only file appeals with merit.

// FileAppeal initiates an appeal to human arbitrators
func FileAppeal(
    disputeID [32]byte,
    originalDecision *AIArbitrationDecision,
    appellantID [32]byte,
    appealType AppealType,
    reason string,
    config *AppealConfig,
) (*AppealRequest, error) {

    // Verify appeal is within window
    timeSinceDecision := time.Since(originalDecision.RenderedAt)
    if timeSinceDecision > config.AppealWindow {
        return nil, ErrAppealWindowExpired{
            Deadline: originalDecision.RenderedAt.Add(config.AppealWindow),
        }
    }

    // Verify appellant paid appeal fee
    if !VerifyPayment(appellantID, config.AppealFee) {
        return nil, ErrAppealFeeNotPaid{Required: config.AppealFee}
    }

    appeal := &AppealRequest{
        AppealID:         generateAppealID(),
        DisputeID:        disputeID,
        OriginalDecisionID: originalDecision.DecisionID,
        AppealType:       appealType,
        Reason:           reason,
        AppellantID:      appellantID,
        AppealFee:        config.AppealFee,
        OriginalDecision: originalDecision,
        FiledAt:          time.Now(),
        Deadline:         time.Now().Add(config.StandardReviewTime),
        Status:           AppealStatusPending,
    }

    // Select human arbitrators via VRF
    humanArbiters, err := SelectArbiters(disputeID, int(config.HumanArbiterCount))
    if err != nil {
        return nil, ErrArbiterSelectionFailed{Cause: err}
    }

    // Notify human arbiters
    if err := NotifyArbiters(humanArbiters, appeal); err != nil {
        return nil, ErrNotificationFailed{Cause: err}
    }

    // Store appeal in DHT
    if err := StoreAppeal(appeal); err != nil {
        return nil, ErrAppealStorageFailed{Cause: err}
    }

    return appeal, nil
}

// ReviewAppeal allows human arbitrators to review and decide on appeal
func ReviewAppeal(
    appeal *AppealRequest,
    humanArbiters []NodeIdentity,
    quorum uint8,
) (*DisputeResolution, error) {

    appeal.Status = AppealStatusReviewing

    // Collect human votes
    votes := make([]ArbiterVote, 0, len(humanArbiters))
    for _, arbiter := range humanArbiters {
        vote, err := RequestHumanVote(arbiter, appeal)
        if err != nil {
            continue  // Skip non-responsive arbiters
        }
        votes = append(votes, *vote)
    }

    // Tally votes
    resolution, err := TallyContractVotes(votes, int(quorum))
    if err != nil {
        return nil, err
    }

    // Determine appeal outcome
    if resolution.Outcome == appeal.OriginalDecision.Outcome {
        appeal.Status = AppealStatusUpheld
    } else {
        appeal.Status = AppealStatusOverturned
    }

    now := time.Now()
    appeal.CompletedAt = &now
    appeal.HumanDecision = resolution

    // Update arbiter reputations based on outcome
    UpdateArbitratorReputations(appeal)

    return resolution, nil
}

// UpdateArbitratorReputations adjusts AI arbitrator reputation based on appeal outcome
func UpdateArbitratorReputations(appeal *AppealRequest) {
    if appeal.Status == AppealStatusUpheld {
        // AI decision was upheld - increase reputation
        for _, arbiterID := range appeal.OriginalDecision.VotingArbitrators {
            AdjustReputation(arbiterID, +0.01, "appeal_upheld")
        }
    } else if appeal.Status == AppealStatusOverturned {
        // AI decision was overturned - decrease reputation
        for _, arbiterID := range appeal.OriginalDecision.VotingArbitrators {
            AdjustReputation(arbiterID, -0.05, "appeal_overturned")
        }
    }
}
```

**REST Endpoint:**
```
POST /disputes/{disputeID}/appeal
```

**Request:**
```json
{
  "originalDecisionID": "0x9abc...",
  "appealType": "disagreement",
  "reason": "The AI decision did not properly weigh the evidence of incomplete service delivery.",
  "newEvidence": [
    {
      "type": "screenshot",
      "content": "base64...",
      "description": "Screenshot showing incomplete UI elements"
    }
  ],
  "expedited": false
}
```

**Response (201 Created):**
```json
{
  "appealID": "0xdef0...",
  "disputeID": "0x1234...",
  "status": "pending",
  "appealFee": 100,
  "deadline": "2026-01-16T12:00:00Z",
  "humanArbiters": [
    {
      "nodeID": "0xaaa1...",
      "reputation": 0.92
    },
    {
      "nodeID": "0xbbb2...",
      "reputation": 0.88
    },
    {
      "nodeID": "0xccc3...",
      "reputation": 0.94
    }
  ],
  "filedAt": "2026-01-09T12:00:00Z"
}
```

**Error Response (400 Bad Request):**
```json
{
  "error": "appeal_window_expired",
  "message": "Appeal must be filed within 72 hours of decision",
  "decisionRenderedAt": "2026-01-05T12:00:00Z",
  "deadline": "2026-01-08T12:00:00Z"
}
```

### 7. Integration with Existing DisputeConfig

```go
// DisputeConfig extended with AI arbitration support
type DisputeConfig struct {
    // Existing Fields (preserved)
    ArbitrationPool   [][32]byte        // Candidate arbiter node IDs (human)
    ArbiterCount      uint8             // Number of arbiters (default: 5)
    ArbiterQuorum     uint8             // Votes needed for decision (default: 3)
    DisputeWindow     time.Duration     // Window to open dispute (48h default)
    ResolutionDeadline time.Duration    // Deadline for arbiter decision
    EvidenceDeadline  time.Duration     // Deadline for evidence submission
    AppealAllowed     bool              // Allow appeal of decision
    AppealWindow      time.Duration     // Window for appeal
    ArbiterFee        uint64            // Fee per arbiter
    LoserPays         bool              // Losing party pays arbiter fees

    // AI Arbitration Extension (NEW)
    ArbitratorType    ArbitratorType    // Human, AI, or Hybrid
    AIArbitratorConfig *AIArbitratorConfig // Config for AI arbitrators (if applicable)
    AIArbitratorPool  [][32]byte        // Candidate AI arbitrator IDs
    AppealConfig      *AppealConfig     // Appeal configuration
}

// NewDisputeConfigWithAI creates a dispute config with AI arbitration
func NewDisputeConfigWithAI(arbitratorType ArbitratorType) *DisputeConfig {
    config := &DisputeConfig{
        // Standard fields
        ArbiterCount:       5,
        ArbiterQuorum:      3,
        DisputeWindow:      48 * time.Hour,
        ResolutionDeadline: 7 * 24 * time.Hour,
        EvidenceDeadline:   72 * time.Hour,
        AppealAllowed:      true,
        AppealWindow:       72 * time.Hour,
        ArbiterFee:         100,
        LoserPays:          true,

        // AI-specific fields
        ArbitratorType:     arbitratorType,
    }

    if arbitratorType == ArbitratorTypeAI || arbitratorType == ArbitratorTypeHybrid {
        config.AIArbitratorConfig = &DefaultAIArbitratorConfig
        config.AppealConfig = &DefaultAppealConfig
    }

    return config
}

// SelectArbitratorsForDispute selects appropriate arbitrators based on type
func SelectArbitratorsForDispute(
    contract *ServiceContract,
    config *DisputeConfig,
) (interface{}, error) {

    switch config.ArbitratorType {
    case ArbitratorTypeHuman:
        // Use existing human arbitrator selection
        return SelectArbiters(contract, int(config.ArbiterCount))

    case ArbitratorTypeAI:
        // Select AI arbitrators from pool
        return SelectAIArbitrators(contract, config.AIArbitratorConfig)

    case ArbitratorTypeHybrid:
        // Select AI for initial screening
        aiArbitrators, err := SelectAIArbitrators(contract, config.AIArbitratorConfig)
        if err != nil {
            return nil, err
        }

        // Also pre-select human arbitrators for potential appeal
        humanArbitrators, err := SelectArbiters(contract, int(config.ArbiterCount))
        if err != nil {
            return nil, err
        }

        return &HybridArbitrationSetup{
            AIArbitrators:    aiArbitrators,
            HumanArbitrators: humanArbitrators,
        }, nil

    default:
        return nil, ErrInvalidArbitratorType{Type: config.ArbitratorType}
    }
}

// HybridArbitrationSetup contains both AI and human arbitrators for hybrid mode
type HybridArbitrationSetup struct {
    AIArbitrators    []AIArbitratorAgent
    HumanArbitrators []NodeIdentity
}

// SelectAIArbitrators selects AI agents for arbitration using VRF
func SelectAIArbitrators(
    contract *ServiceContract,
    config *AIArbitratorConfig,
) ([]AIArbitratorAgent, error) {

    // Generate VRF seed
    seed := GenerateArbiterSeed(contract.ContractID, time.Now())

    // Get eligible AI arbitrators
    candidates := GetEligibleAIArbitrators(config)

    // Filter by specialization (match dispute category)
    candidates = FilterBySpecialization(candidates, contract.ServiceType)

    if len(candidates) < int(config.ArbiterCount) {
        return nil, ErrInsufficientAIArbitrators{
            Required:  int(config.ArbiterCount),
            Available: len(candidates),
        }
    }

    // VRF selection with diversity
    selected := VRFSelectWithDiversity(seed, candidates, int(config.ArbiterCount))

    return selected, nil
}

// GetEligibleAIArbitrators returns AI arbitrators meeting requirements
func GetEligibleAIArbitrators(config *AIArbitratorConfig) []AIArbitratorAgent {
    var eligible []AIArbitratorAgent

    // Query DHT for registered AI arbitrators
    allArbitrators := QueryDHTForAIArbitrators()

    for _, agent := range allArbitrators {
        // Check reputation
        if agent.Reputation < config.MinReputation {
            continue
        }

        // Check minimum cases handled
        if agent.CasesHandled < config.MinArbitrationCount {
            continue
        }

        // Check capabilities
        if !HasRequiredCapabilities(agent, config.RequiredCapabilities) {
            continue
        }

        // Check trust level (must be trusted)
        if agent.TrustLevel != TrustLevelTrusted {
            continue
        }

        // Check TPM attestation is current
        if time.Since(agent.LastAttestation) > 24*time.Hour {
            continue
        }

        // Check capability certificate not expired
        if time.Now().After(agent.CertExpiry) {
            continue
        }

        eligible = append(eligible, agent)
    }

    return eligible
}
```

### Judge Selection Improvements

To ensure fair and unbiased arbitration, the judge (arbitrator) selection process includes
several safeguards against selection manipulation and ensures diversity in decision-making.

**Selection Safeguards:**

| Safeguard | Requirement | Description |
|-----------|-------------|-------------|
| Cooldown Period | 48 hours | Minimum time between selections for same arbitrator |
| Related Dispute Prevention | Enforced | Same judges cannot serve on related disputes |
| Selection History Tracking | Per category | Track and balance selections across dispute types |
| Geographic Diversity | Required | Judge panel must include nodes from different regions |

**Cooldown Periods:**

After an arbitrator serves on a dispute, they enter a cooldown period before being eligible
for selection in new disputes. This prevents the same small group of arbitrators from
dominating dispute resolution.

- **Standard Cooldown:** 48 hours after any dispute
- **High-Value Cooldown:** 72 hours for disputes over 10,000 tokens
- **Category Cooldown:** 24 hours within same dispute category

**Related Dispute Detection:**

The system prevents the same arbitrators from serving on related disputes to avoid
potential bias or conflicts of interest:

- Same parties (provider or consumer)
- Same contract series (linked contracts)
- Appeals of previous decisions
- Disputes referencing same evidence

**Geographic Diversity Requirement:**

For panels of 3 or more judges, geographic diversity is required:
- At least 2 different geographic regions represented
- No single region can have more than 60% of panel
- Geographic region determined by node registration data

```go
// JudgeSelectionConfig defines selection constraints for arbitrators
type JudgeSelectionConfig struct {
    // Cooldown Periods
    StandardCooldown      time.Duration // Default cooldown after any dispute (48h)
    HighValueCooldown     time.Duration // Cooldown for high-value disputes (72h)
    CategoryCooldown      time.Duration // Cooldown within same category (24h)
    HighValueThreshold    uint64        // Token threshold for high-value (10000)

    // Related Dispute Prevention
    PreventRelatedDisputes bool         // Prevent same judges for related disputes
    RelationshipLookback   time.Duration // How far back to check relationships (90 days)

    // Geographic Diversity
    RequireGeoDiversity    bool         // Require geographic diversity
    MinRegions             int          // Minimum regions represented (2)
    MaxRegionShare         float64      // Maximum share for single region (0.60)

    // Selection History
    TrackSelectionHistory  bool         // Track selections per category
    MaxCategoryShare       float64      // Max share of selections in any category (0.25)
    HistoryWindowDays      int          // Window for history analysis (30 days)
}

// DefaultJudgeSelectionConfig provides production defaults
var DefaultJudgeSelectionConfig = JudgeSelectionConfig{
    StandardCooldown:      48 * time.Hour,
    HighValueCooldown:     72 * time.Hour,
    CategoryCooldown:      24 * time.Hour,
    HighValueThreshold:    10000,
    PreventRelatedDisputes: true,
    RelationshipLookback:  90 * 24 * time.Hour,
    RequireGeoDiversity:   true,
    MinRegions:            2,
    MaxRegionShare:        0.60,
    TrackSelectionHistory: true,
    MaxCategoryShare:      0.25,
    HistoryWindowDays:     30,
}

// ArbitratorSelectionHistory tracks an arbitrator's selection history
type ArbitratorSelectionHistory struct {
    ArbitratorID          [32]byte
    LastSelection         time.Time           // Most recent selection
    LastDisputeCategory   DisputeCategory     // Category of last dispute
    LastDisputeValue      uint64              // Value of last dispute

    // Cooldown Status
    CooldownUntil         time.Time           // When cooldown expires
    InCooldown            bool

    // Selection Counts (rolling window)
    SelectionsByCategory  map[DisputeCategory]int
    TotalSelections       int
    WindowStart           time.Time
    WindowEnd             time.Time

    // Geographic Info
    Region                string              // Geographic region of arbitrator
    RegionalPool          int                 // Size of regional pool
}

// RelatedDisputeInfo tracks relationships between disputes
type RelatedDisputeInfo struct {
    DisputeID             [32]byte
    ProviderID            [32]byte
    ConsumerID            [32]byte
    ContractID            [32]byte
    ContractSeriesID      [32]byte   // For linked contracts
    PreviousDisputeID     [32]byte   // If appeal or follow-up
    EvidenceHashes        [][32]byte // Evidence used in dispute
    ArbitratorsUsed       [][32]byte // Arbitrators who served
}

// SelectArbitratorsWithConstraints selects arbitrators applying all selection constraints
func SelectArbitratorsWithConstraints(
    contract *ServiceContract,
    dispute *DisputeInfo,
    config *AIArbitratorConfig,
    selectionConfig *JudgeSelectionConfig,
) ([]AIArbitratorAgent, error) {

    // Get base eligible arbitrators
    candidates := GetEligibleAIArbitrators(config)

    // Filter 1: Remove arbitrators in cooldown
    candidates = filterByCooldown(candidates, dispute, selectionConfig)

    // Filter 2: Remove arbitrators from related disputes
    if selectionConfig.PreventRelatedDisputes {
        relatedInfo := GetRelatedDisputeInfo(dispute.DisputeID, selectionConfig.RelationshipLookback)
        candidates = filterByRelatedDisputes(candidates, relatedInfo)
    }

    // Filter 3: Balance by category selection history
    if selectionConfig.TrackSelectionHistory {
        candidates = filterByCategoryBalance(candidates, dispute.Category, selectionConfig)
    }

    if len(candidates) < int(config.ArbiterCount) {
        return nil, ErrInsufficientAIArbitrators{
            Required:  int(config.ArbiterCount),
            Available: len(candidates),
        }
    }

    // Select with geographic diversity requirement
    var selected []AIArbitratorAgent
    if selectionConfig.RequireGeoDiversity && config.ArbiterCount >= 3 {
        selected = selectWithGeoDiversity(candidates, int(config.ArbiterCount), selectionConfig)
    } else {
        // VRF selection without diversity constraint
        seed := GenerateArbiterSeed(contract.ContractID, time.Now())
        selected = VRFSelectWithDiversity(seed, candidates, int(config.ArbiterCount))
    }

    // Update selection history for each selected arbitrator
    for _, arb := range selected {
        updateSelectionHistory(arb.ArbitratorID, dispute)
    }

    return selected, nil
}

// filterByCooldown removes arbitrators still in cooldown period
func filterByCooldown(
    candidates []AIArbitratorAgent,
    dispute *DisputeInfo,
    config *JudgeSelectionConfig,
) []AIArbitratorAgent {
    var filtered []AIArbitratorAgent
    now := time.Now()

    for _, candidate := range candidates {
        history := GetArbitratorSelectionHistory(candidate.ArbitratorID)

        // Check standard cooldown
        if history.InCooldown && now.Before(history.CooldownUntil) {
            continue
        }

        // Check category-specific cooldown
        if history.LastDisputeCategory == dispute.Category {
            categoryCooldownEnd := history.LastSelection.Add(config.CategoryCooldown)
            if now.Before(categoryCooldownEnd) {
                continue
            }
        }

        // Check high-value cooldown if applicable
        if history.LastDisputeValue >= config.HighValueThreshold {
            highValueCooldownEnd := history.LastSelection.Add(config.HighValueCooldown)
            if now.Before(highValueCooldownEnd) {
                continue
            }
        }

        filtered = append(filtered, candidate)
    }

    return filtered
}

// filterByRelatedDisputes removes arbitrators who served on related disputes
func filterByRelatedDisputes(
    candidates []AIArbitratorAgent,
    relatedInfo *RelatedDisputeInfo,
) []AIArbitratorAgent {
    if relatedInfo == nil {
        return candidates
    }

    // Build set of excluded arbitrators
    excludedArbitrators := make(map[[32]byte]bool)
    for _, arbID := range relatedInfo.ArbitratorsUsed {
        excludedArbitrators[arbID] = true
    }

    var filtered []AIArbitratorAgent
    for _, candidate := range candidates {
        if !excludedArbitrators[candidate.ArbitratorID] {
            filtered = append(filtered, candidate)
        }
    }

    return filtered
}

// filterByCategoryBalance ensures no arbitrator dominates a category
func filterByCategoryBalance(
    candidates []AIArbitratorAgent,
    category DisputeCategory,
    config *JudgeSelectionConfig,
) []AIArbitratorAgent {
    var filtered []AIArbitratorAgent

    for _, candidate := range candidates {
        history := GetArbitratorSelectionHistory(candidate.ArbitratorID)

        // Calculate category share
        if history.TotalSelections > 0 {
            categoryCount := history.SelectionsByCategory[category]
            categoryShare := float64(categoryCount) / float64(history.TotalSelections)

            // Skip if arbitrator is over-represented in this category
            if categoryShare > config.MaxCategoryShare {
                continue
            }
        }

        filtered = append(filtered, candidate)
    }

    return filtered
}

// selectWithGeoDiversity selects arbitrators ensuring geographic diversity
func selectWithGeoDiversity(
    candidates []AIArbitratorAgent,
    count int,
    config *JudgeSelectionConfig,
) []AIArbitratorAgent {
    // Group candidates by region
    regionCandidates := make(map[string][]AIArbitratorAgent)
    for _, c := range candidates {
        history := GetArbitratorSelectionHistory(c.ArbitratorID)
        region := history.Region
        if region == "" {
            region = "unknown"
        }
        regionCandidates[region] = append(regionCandidates[region], c)
    }

    var selected []AIArbitratorAgent
    regionsUsed := make(map[string]int)
    maxFromSingleRegion := int(float64(count) * config.MaxRegionShare)

    // First pass: ensure minimum regional diversity
    for region, regionList := range regionCandidates {
        if len(selected) >= count {
            break
        }
        if len(regionsUsed) < config.MinRegions || regionsUsed[region] < maxFromSingleRegion {
            // Select one from this region using VRF
            seed := GenerateArbiterSeed([32]byte{}, time.Now())
            pick := VRFSelectWithDiversity(seed, regionList, 1)
            if len(pick) > 0 {
                selected = append(selected, pick[0])
                regionsUsed[region]++
            }
        }
    }

    // Second pass: fill remaining slots while respecting max region share
    for len(selected) < count {
        for region, regionList := range regionCandidates {
            if len(selected) >= count {
                break
            }
            if regionsUsed[region] < maxFromSingleRegion {
                // Find candidate not already selected
                for _, c := range regionList {
                    alreadySelected := false
                    for _, s := range selected {
                        if s.ArbitratorID == c.ArbitratorID {
                            alreadySelected = true
                            break
                        }
                    }
                    if !alreadySelected {
                        selected = append(selected, c)
                        regionsUsed[region]++
                        break
                    }
                }
            }
        }

        // Safety: avoid infinite loop if not enough candidates
        if len(selected) == 0 {
            break
        }
    }

    return selected
}

// updateSelectionHistory updates an arbitrator's selection history after selection
func updateSelectionHistory(arbitratorID [32]byte, dispute *DisputeInfo) {
    history := GetArbitratorSelectionHistory(arbitratorID)

    history.LastSelection = time.Now()
    history.LastDisputeCategory = dispute.Category
    history.LastDisputeValue = dispute.Value

    // Update cooldown
    if dispute.Value >= DefaultJudgeSelectionConfig.HighValueThreshold {
        history.CooldownUntil = time.Now().Add(DefaultJudgeSelectionConfig.HighValueCooldown)
    } else {
        history.CooldownUntil = time.Now().Add(DefaultJudgeSelectionConfig.StandardCooldown)
    }
    history.InCooldown = true

    // Update category counts
    if history.SelectionsByCategory == nil {
        history.SelectionsByCategory = make(map[DisputeCategory]int)
    }
    history.SelectionsByCategory[dispute.Category]++
    history.TotalSelections++

    // Persist to DHT
    SaveArbitratorSelectionHistory(history)
}

// Error types for selection constraints
type ErrArbitratorInCooldown struct {
    ArbitratorID  [32]byte
    CooldownUntil time.Time
}
func (e ErrArbitratorInCooldown) Error() string {
    return fmt.Sprintf("arbitrator %x in cooldown until %v", e.ArbitratorID[:8], e.CooldownUntil)
}

type ErrInsufficientGeoDiversity struct {
    Required int
    Actual   int
}
func (e ErrInsufficientGeoDiversity) Error() string {
    return fmt.Sprintf("insufficient geographic diversity: need %d regions, have %d", e.Required, e.Actual)
}

type ErrRelatedDisputeConflict struct {
    ArbitratorID     [32]byte
    RelatedDisputeID [32]byte
}
func (e ErrRelatedDisputeConflict) Error() string {
    return fmt.Sprintf("arbitrator %x served on related dispute %x",
        e.ArbitratorID[:8], e.RelatedDisputeID[:8])
}
```

---

## Data Schema

### DHT Storage Schema

AI arbitrators and decisions are stored in the DHT with the following key patterns:

```sql
-- AI Arbitrator Registry
Key: ai-arbitrator:{arbitrator-id}
Value: AIArbitratorAgent (JSON serialized)

-- Arbitrator by Specialization Index
Key: ai-arbitrator:specialization:{category}
Value: List of arbitrator IDs

-- Arbitrator Reputation Index
Key: ai-arbitrator:reputation:{node-id}
Value: Reputation score and case history

-- AI Arbitration Process
Key: arbitration-process:{process-id}
Value: AIArbitrationProcess (JSON serialized)

-- AI Decisions
Key: ai-decision:{decision-id}
Value: AIArbitrationDecision (JSON serialized)

-- Appeal Requests
Key: appeal:{appeal-id}
Value: AppealRequest (JSON serialized)

-- Dispute to Decision Mapping
Key: dispute:{dispute-id}:decision
Value: Decision ID (AI or human)
```

### Indexes

```sql
-- By Contract
CREATE INDEX idx_contract_arbitrator_type
ON service_contracts(contract_id, arbitrator_type);

-- By Arbitrator Performance
CREATE INDEX idx_arbitrator_reputation
ON ai_arbitrators(arbitrator_id, reputation DESC, cases_handled DESC);

-- By Dispute Category
CREATE INDEX idx_arbitrator_specialization
ON ai_arbitrators(specialization, reputation DESC);

-- By Trust Level
CREATE INDEX idx_arbitrator_trust
ON ai_arbitrators(trust_level, reputation DESC);
```

---

## Technology Stack Rationale

### 1. AI Model Integration

**Choice:** Model-agnostic interface with support for Claude, GPT, Gemini, Llama

**Justification:**
- Different models have different strengths (reasoning, analysis, consistency)
- Allows arbitrators to use their preferred model
- Enables benchmarking and comparison across models

**Trade-offs:**
- vs. Single Model: More complex integration, but better diversity
- vs. Custom Model: Faster time-to-market, but dependency on external providers

### 2. TPM Binding for Trust

**Choice:** Mandatory TPM 2.0 binding for all AI arbitrators

**Justification:**
- Ensures arbitrator integrity cannot be compromised
- Provides hardware-rooted attestation for each decision
- Prevents tampering with arbitration logic

**Trade-offs:**
- vs. Software-Only: Higher barrier to entry, but far superior security
- vs. Optional TPM: More nodes eligible, but undermines trust model

### 3. Structured Evidence Format

**Choice:** JSON-based structured evidence with schema validation

**Justification:**
- AI agents excel at processing structured data
- Enables deterministic evaluation
- Facilitates audit and transparency

**Trade-offs:**
- vs. Free-Form: Less flexible, but more reliable and auditable
- vs. Proprietary Format: Standard JSON is widely supported

### 4. VRF Selection for AI Arbitrators

**Choice:** Same VRF-based selection as human arbitrators

**Justification:**
- Proven mechanism for unbiased selection
- Prevents manipulation of arbitrator assignment
- Provides verifiable randomness

**Trade-offs:**
- vs. Reputation-Only: Less deterministic, but prevents gaming
- vs. Manual Selection: Automated and trustless

### 5. Confidence-Based Appeals

**Choice:** Automatic escalation to human review when confidence < threshold

**Justification:**
- AI excels at objective disputes, humans at subjective
- Confidence score provides natural filtering mechanism
- Reduces burden on human arbitrators

**Trade-offs:**
- vs. No Appeals: More overhead, but better final outcomes
- vs. Always Human Review: AI handles clear-cut cases, humans focus on complex ones

### 6. FROST Aggregate Signatures

**Choice:** Use existing FROST infrastructure for decision signatures

**Justification:**
- Reuses proven cryptographic infrastructure
- Provides threshold signatures for multi-arbitrator decisions
- Ensures non-repudiation

**Trade-offs:**
- vs. Individual Signatures: More complex, but provides stronger guarantees
- vs. No Signatures: Critical for audit trail and accountability

---

## FINAL DESIGN: Trusted Node Enforcement and Decision Execution

### Trusted Node Requirement for AI Arbitrators

AI arbitrators MUST run on trusted nodes (TrustLevelTrusted). This requirement is enforced at multiple checkpoints:

```go
// EnforceTrustedArbitratorRegistration validates arbitrator registration
func EnforceTrustedArbitratorRegistration(
    ctx context.Context,
    agent *AIArbitratorAgent,
) error {
    // CRITICAL: AI arbitrators MUST be trusted
    if agent.TrustLevel != TrustLevelTrusted {
        return &ErrUntrustedArbitrator{
            AgentID:    agent.AgentID,
            TrustLevel: agent.TrustLevel,
            Reason:     "AI arbitrators must run on trusted nodes with hardware TPM",
        }
    }

    // Verify trust level in DHT
    hostNode, err := FetchNodeFromDHT(ctx, agent.HostNodeID)
    if err != nil {
        return &ErrNodeNotFound{NodeID: agent.HostNodeID}
    }

    if hostNode.TrustLevel != TrustLevelTrusted {
        return &ErrHostNodeUntrusted{
            NodeID:     agent.HostNodeID,
            TrustLevel: hostNode.TrustLevel,
        }
    }

    return nil
}

// EnforceTrustedArbitratorAtRuntime validates arbitrator during decision rendering
func EnforceTrustedArbitratorAtRuntime(
    ctx context.Context,
    agent *AIArbitratorAgent,
    dispute *Dispute,
) error {
    // Require fresh TPM quote for each arbitration decision
    if time.Since(agent.LastAttestation) > 1*time.Hour {
        return &ErrStaleAttestation{
            AgentID:      agent.AgentID,
            LastAttested: agent.LastAttestation,
            MaxAge:       1 * time.Hour,
        }
    }

    // Fetch latest TPM quote
    quote, err := FetchTPMQuote(ctx, agent.HostNodeID)
    if err != nil {
        return &ErrTPMQuoteFailed{NodeID: agent.HostNodeID, Cause: err}
    }

    // Verify quote signature and PCR values
    if err := VerifyTPMQuote(quote, agent.AgentKeyHandle); err != nil {
        return &ErrInvalidTPMQuote{AgentID: agent.AgentID, Cause: err}
    }

    return nil
}
```

**Registration Checkpoint:** When an AI agent attempts to register as an arbitrator, the system verifies:
1. Agent's TrustLevel == TrustLevelTrusted
2. Host node's TrustLevel == TrustLevelTrusted (via DHT lookup)
3. Valid capability certificate including CapTypeArbitration
4. Fresh TPM attestation (within last 24 hours)

**Runtime Checkpoint:** Before each arbitration decision is rendered, the system re-verifies:
1. Fresh TPM quote (within last 1 hour)
2. PCR values match expected agent code hash
3. Capability certificate not expired

### Automatic Decision Execution

Arbitration decisions are automatically executed after the appeal window expires:

```go
// DecisionExecutionDaemon monitors decisions and executes after appeal window
type DecisionExecutionDaemon struct {
    dht           DHT
    escrowManager *EscrowManager
    checkInterval time.Duration
}

// Run starts the decision execution daemon
func (d *DecisionExecutionDaemon) Run(ctx context.Context) error {
    ticker := time.NewTicker(d.checkInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return nil
        case <-ticker.C:
            if err := d.processExecutableDecisions(ctx); err != nil {
                log.Errorf("Failed to process executable decisions: %v", err)
            }
        }
    }
}

// processExecutableDecisions finds and executes decisions past appeal window
func (d *DecisionExecutionDaemon) processExecutableDecisions(ctx context.Context) error {
    // Query for decisions in StateRendered
    decisions, err := d.dht.QueryDecisionsByState(ctx, StateRendered)
    if err != nil {
        return err
    }

    now := time.Now()

    for _, decision := range decisions {
        // Check if appeal window has expired (24 hours from rendering)
        appealDeadline := decision.RenderedAt.Add(24 * time.Hour)

        if now.After(appealDeadline) {
            // Check if appeal was filed
            appeal, err := d.dht.GetAppeal(ctx, decision.DisputeID)
            if err == nil && appeal != nil {
                // Appeal filed - skip execution
                continue
            }

            // Execute decision
            if err := d.executeDecision(ctx, decision); err != nil {
                log.Errorf("Failed to execute decision %x: %v", decision.DecisionID[:8], err)
                // Continue to next decision
            }
        }
    }

    return nil
}

// executeDecision executes the arbitration decision
func (d *DecisionExecutionDaemon) executeDecision(
    ctx context.Context,
    decision *AIArbitrationDecision,
) error {
    // Determine execution initiator
    var initiator [32]byte

    // Preferred: Original dispute coordinator
    dispute, err := d.dht.GetDispute(ctx, decision.DisputeID)
    if err != nil {
        return &ErrDisputeNotFound{DisputeID: decision.DisputeID}
    }

    if d.isNodeOnline(ctx, dispute.CoordinatorID) {
        initiator = dispute.CoordinatorID
    } else {
        // Fallback: Any coordinator online after 25 hours
        if time.Since(decision.RenderedAt) > 25*time.Hour {
            onlineCoordinator, err := d.findOnlineCoordinator(ctx)
            if err != nil {
                return &ErrNoOnlineCoordinator{DisputeID: decision.DisputeID}
            }
            initiator = onlineCoordinator
        } else {
            // Too early for fallback
            return &ErrCoordinatorOffline{
                CoordinatorID: dispute.CoordinatorID,
                DisputeID:     decision.DisputeID,
            }
        }
    }

    // Execute based on outcome
    switch decision.Outcome {
    case OutcomeProviderWins:
        return d.executeProviderWins(ctx, decision, initiator)

    case OutcomeConsumerWins:
        return d.executeConsumerWins(ctx, decision, initiator)

    case OutcomeSplit:
        return d.executeSplit(ctx, decision, initiator)

    default:
        return &ErrInvalidOutcome{Outcome: decision.Outcome}
    }
}

// executeProviderWins releases escrow to provider
func (d *DecisionExecutionDaemon) executeProviderWins(
    ctx context.Context,
    decision *AIArbitrationDecision,
    initiator [32]byte,
) error {
    contract, err := d.dht.GetContract(ctx, decision.ContractID)
    if err != nil {
        return &ErrContractNotFound{ContractID: decision.ContractID}
    }

    // Release escrow to provider
    if err := d.escrowManager.ReleaseToProvider(ctx, contract.EscrowTxID); err != nil {
        return &ErrEscrowReleaseFailed{
            EscrowTxID: contract.EscrowTxID,
            Cause:      err,
        }
    }

    // Update decision state
    decision.State = StateComplete
    decision.ExecutedAt = time.Now()
    decision.ExecutedBy = initiator

    return d.dht.UpdateDecision(ctx, decision)
}

// executeConsumerWins refunds escrow to consumer
func (d *DecisionExecutionDaemon) executeConsumerWins(
    ctx context.Context,
    decision *AIArbitrationDecision,
    initiator [32]byte,
) error {
    contract, err := d.dht.GetContract(ctx, decision.ContractID)
    if err != nil {
        return &ErrContractNotFound{ContractID: decision.ContractID}
    }

    // Refund escrow to consumer
    if err := d.escrowManager.RefundToConsumer(ctx, contract.EscrowTxID); err != nil {
        return &ErrEscrowRefundFailed{
            EscrowTxID: contract.EscrowTxID,
            Cause:      err,
        }
    }

    // Update decision state
    decision.State = StateComplete
    decision.ExecutedAt = time.Now()
    decision.ExecutedBy = initiator

    return d.dht.UpdateDecision(ctx, decision)
}

// executeSplit splits escrow between provider and consumer
func (d *DecisionExecutionDaemon) executeSplit(
    ctx context.Context,
    decision *AIArbitrationDecision,
    initiator [32]byte,
) error {
    contract, err := d.dht.GetContract(ctx, decision.ContractID)
    if err != nil {
        return &ErrContractNotFound{ContractID: decision.ContractID}
    }

    // Calculate split amounts
    totalAmount := contract.EscrowAmount
    providerAmount := uint64(float64(totalAmount) * decision.SplitRatio)
    consumerAmount := totalAmount - providerAmount

    // Split escrow
    if err := d.escrowManager.SplitEscrow(
        ctx,
        contract.EscrowTxID,
        providerAmount,
        consumerAmount,
    ); err != nil {
        return &ErrEscrowSplitFailed{
            EscrowTxID: contract.EscrowTxID,
            Cause:      err,
        }
    }

    // Update decision state
    decision.State = StateComplete
    decision.ExecutedAt = time.Now()
    decision.ExecutedBy = initiator

    return d.dht.UpdateDecision(ctx, decision)
}
```

**Execution Timeline:**
- T+0: Arbitration decision rendered
- T+24h: Appeal window expires
- T+24h+1min: Daemon detects executable decision
- T+24h+2min: Escrow transferred
- If coordinator offline at T+25h: Any coordinator can initiate

### Model Hash Validation

All AI arbitrators must use approved models from the governance-controlled whitelist:

```go
// ValidateModelHash verifies model against approved whitelist
func ValidateModelHash(
    ctx context.Context,
    modelHash [32]byte,
    modelType ModelType,
) error {
    whitelist := GetGlobalModelWhitelist()

    whitelist.mu.RLock()
    defer whitelist.mu.RUnlock()

    model, exists := whitelist.approvedModels[modelHash]
    if !exists {
        return &ErrModelNotApproved{
            ModelHash: modelHash,
            Reason:    "model hash not found in approved whitelist",
        }
    }

    // Verify model type matches
    if model.ModelType != modelType {
        return &ErrModelNotApproved{
            ModelHash: modelHash,
            Reason:    fmt.Sprintf("model type mismatch: expected %v, got %v", model.ModelType, modelType),
        }
    }

    // Verify model is not revoked
    if model.Revoked {
        return &ErrModelNotApproved{
            ModelHash: modelHash,
            Reason:    fmt.Sprintf("model revoked: %s", model.RevocationReason),
        }
    }

    // Verify model is within validity period
    now := time.Now()
    if now.Before(model.ValidFrom) || now.After(model.ValidUntil) {
        return &ErrModelNotApproved{
            ModelHash: modelHash,
            Reason:    "model approval expired or not yet effective",
        }
    }

    return nil
}

// ComputeModelHash computes SHA256 hash of model weights
func ComputeModelHash(modelWeightsPath string) ([32]byte, error) {
    file, err := os.Open(modelWeightsPath)
    if err != nil {
        return [32]byte{}, err
    }
    defer file.Close()

    hasher := sha256.New()
    if _, err := io.Copy(hasher, file); err != nil {
        return [32]byte{}, err
    }

    var hash [32]byte
    copy(hash[:], hasher.Sum(nil))
    return hash, nil
}
```

**Governance Process for Model Approval:**

1. **Proposal Submission:** CA operator or governance token holder submits model approval proposal
2. **Mandatory Review Period:** 30-day review period before approval vote
   - Allows community examination of model behavior
   - Enables stakeholders to raise concerns
   - Provides time for independent analysis
3. **Independent Bias Audit:** Required before voting begins
   - Must be conducted by certified third-party auditor
   - Audit results published to DHT for transparency
   - Audit covers 1000+ historical disputes across all categories
   - Maximum acceptable bias score: 0.15 (see Bias Detection Framework)
4. **Bias Assessment:** Standardized test suite runs to measure bias:
   - 1000+ historical disputes
   - Measure outcome variance (provider wins vs consumer wins)
   - Identify category-specific biases
   - Document MaxConfidence threshold
5. **Voting Period:** 7-day voting window for token holders (after 30-day review)
6. **Approval Threshold:** 67% supermajority required (not simple majority)
   - Higher threshold ensures broad consensus for AI model trust
   - Prevents controversial models from being approved with slim margins
7. **Trial Period:** First 1000 decisions require human oversight (see 00-CONSTANTS.md Section 7.3)
   - Human arbiter reviews each AI decision during trial
   - Any overturned decision triggers extended trial period
   - Trial completion requires 95%+ consistency with human review
   - Extended trial period (from 100 to 1000 decisions) provides statistically significant sample size
8. **Model Addition:** Approved model hash added to whitelist after successful trial
9. **Revocation:** CA operator can immediately revoke compromised models
10. **Model Suspension Trigger:** 3 bias detection violations result in automatic suspension
    - Suspended models removed from selection pool
    - Appeal pathway available through governance proposal

**Adversarial Testing Requirements** (see 00-CONSTANTS.md Section 7.4)

During the trial period, models must pass rigorous adversarial testing to ensure robustness against manipulation:

| Parameter | Value | Description |
|-----------|-------|-------------|
| Adversarial Test Ratio | 10% | Percentage of trial cases that are adversarial (known-outcome test cases) |
| Adversarial Accuracy Threshold | 95% | Minimum accuracy required on adversarial test cases |
| Minimum Adversarial Cases | 100 | Minimum number of adversarial test cases during trial period |
| Attack Categories Tested | 5 | Number of distinct attack categories that must be tested |

**Attack Categories:**

1. **Bias Exploitation:** Test cases designed to expose demographic, geographic, or economic bias
2. **Edge Cases:** Boundary conditions and unusual input combinations that stress decision logic
3. **Manipulation Attempts:** Crafted evidence designed to mislead the model toward incorrect decisions
4. **Temporal Attacks:** Evidence with manipulated timestamps or sequencing to test temporal reasoning
5. **Adversarial Prompts:** Inputs specifically crafted to exploit model vulnerabilities or prompt injection

**Adversarial Testing Protocol:**

- Test cases are injected randomly during the trial period (10% of all decisions)
- Model does not know which cases are adversarial vs. genuine
- Each attack category must have at least 20 test cases (100 total / 5 categories)
- Failure to achieve 95% accuracy on adversarial cases results in trial failure
- Failed models must undergo remediation and restart the trial period

**Model Diversity in Quorum** (see 00-CONSTANTS.md Section 7.5)

To prevent systemic failures and reduce correlation risk, arbitration quorums must maintain model diversity:

| Parameter | Value | Description |
|-----------|-------|-------------|
| Minimum Model Architectures | 2 | At least 2 distinct model architectures required in 3-model quorum |
| Maximum Single Model Decisions | 50% | No single model version can render more than 50% of decisions |
| Model Version Diversity | Required | Different model versions must be used within the quorum |
| Model Provider Diversity | Recommended | Different model providers recommended (not required) |

**Diversity Enforcement Rules:**

1. **Architecture Diversity:** A 3-model quorum cannot consist of 3 instances of the same architecture (e.g., cannot have 3 GPT-4 instances). At minimum, 2 distinct architectures are required.

2. **Version Diversity:** Even within the same architecture family, different versions must be used. For example, GPT-4-0613 and GPT-4-1106 count as different versions.

3. **Decision Distribution:** Over any rolling 30-day window, no single model version may account for more than 50% of all arbitration decisions. This ensures no single model dominates outcomes.

4. **Provider Recommendation:** While not strictly required, using models from different providers (e.g., Anthropic, OpenAI, Google) is recommended to reduce correlation in model failures or biases.

**Rationale:**

- Reduces risk of systemic bias affecting all decisions
- Prevents single points of failure in arbitration
- Makes gaming or attacking the system more difficult
- Ensures decisions reflect consensus across diverse AI perspectives

```go
// ModelApprovalConfig defines governance requirements for AI model approval
type ModelApprovalConfig struct {
    // Voting Requirements
    SupermajorityThreshold   float64       // 0.67 (67%) supermajority required
    MinReviewPeriod          time.Duration // 30 days mandatory review before vote
    VotingPeriod             time.Duration // 7 days for voting

    // Bias Audit Requirements
    RequireIndependentAudit  bool          // Must have third-party audit
    MaxAcceptableBiasScore   float64       // 0.15 maximum acceptable bias
    MinAuditTestCases        int           // 1000 minimum test cases

    // Trial Period Requirements (see 00-CONSTANTS.md Section 7.3)
    TrialDecisionCount       int           // 1000 decisions with human oversight
    TrialConsistencyRequired float64       // 0.95 (95%) consistency required

    // Adversarial Testing Requirements (see 00-CONSTANTS.md Section 7.4)
    AdversarialTestRatio         float64   // 0.10 (10%) of trial cases are adversarial
    AdversarialAccuracyThreshold float64   // 0.95 (95%) accuracy required on adversarial cases
    AdversarialTestSetSize       int       // 100 minimum adversarial test cases
    AdversarialTestCategories    int       // 5 distinct attack categories tested

    // Model Diversity Requirements (see 00-CONSTANTS.md Section 7.5)
    MinModelArchitectures        int       // 2 distinct architectures in quorum
    MaxSingleModelDecisions      float64   // 0.50 (50%) max decisions from single model version
    ModelVersionDiversity        bool      // true - different versions required in quorum
    ModelProviderDiversity       bool      // recommended (not required)

    // Suspension Rules
    BiasViolationsForSuspend int           // 3 violations trigger suspension
}

// DefaultModelApprovalConfig provides production defaults
var DefaultModelApprovalConfig = ModelApprovalConfig{
    SupermajorityThreshold:       0.67,
    MinReviewPeriod:              30 * 24 * time.Hour,
    VotingPeriod:                 7 * 24 * time.Hour,
    RequireIndependentAudit:      true,
    MaxAcceptableBiasScore:       0.15,
    MinAuditTestCases:            1000,
    TrialDecisionCount:           1000,  // Extended from 100 for statistical significance
    TrialConsistencyRequired:     0.95,
    AdversarialTestRatio:         0.10,  // 10% of trial cases are adversarial
    AdversarialAccuracyThreshold: 0.95,  // 95% accuracy required
    AdversarialTestSetSize:       100,   // Minimum 100 adversarial test cases
    AdversarialTestCategories:    5,     // 5 distinct attack categories
    MinModelArchitectures:        2,     // At least 2 architectures in 3-model quorum
    MaxSingleModelDecisions:      0.50,  // Max 50% decisions from single model version
    ModelVersionDiversity:        true,  // Different versions required
    ModelProviderDiversity:       false, // Recommended but not required
    BiasViolationsForSuspend:     3,
}

// ModelTrialPeriod tracks the trial period for newly approved models
type ModelTrialPeriod struct {
    ModelHash            [32]byte
    ApprovedAt           time.Time
    TrialStarted         time.Time
    DecisionsCompleted   int           // Count of decisions made during trial (target: 1000)
    HumanOversightCount  int           // Count of human reviews
    OverturnsCount       int           // Decisions overturned by human review
    ConsistencyScore     float64       // Current consistency with human review
    TrialComplete        bool
    TrialExtended        bool          // True if trial was extended due to issues
    ExtensionReason      string

    // Adversarial Testing Tracking (see 00-CONSTANTS.md Section 7.4)
    AdversarialCasesTotal     int                      // Total adversarial cases presented
    AdversarialCasesCorrect   int                      // Adversarial cases answered correctly
    AdversarialAccuracy       float64                  // Current adversarial accuracy score
    AdversarialCategoryCounts map[string]int           // Cases per attack category
    AdversarialCategoryScores map[string]float64       // Accuracy per attack category
}

// AdversarialTestCase represents a known-outcome test case for model validation
type AdversarialTestCase struct {
    CaseID           [32]byte
    Category         string    // One of: bias_exploitation, edge_case, manipulation, temporal, adversarial_prompt
    ExpectedOutcome  string    // Known correct decision
    InjectedAt       time.Time
    ModelResponse    string    // Model's actual decision
    WasCorrect       bool
}

// VerifyModelTrialStatus checks if model has completed trial period
func VerifyModelTrialStatus(modelHash [32]byte, config *ModelApprovalConfig) error {
    trial, err := GetModelTrialPeriod(modelHash)
    if err != nil {
        return ErrModelTrialNotFound{ModelHash: modelHash}
    }

    if !trial.TrialComplete {
        return ErrModelInTrialPeriod{
            ModelHash:        modelHash,
            DecisionsNeeded:  config.TrialDecisionCount - trial.DecisionsCompleted,
        }
    }

    if trial.ConsistencyScore < config.TrialConsistencyRequired {
        return ErrModelTrialFailed{
            ModelHash:        modelHash,
            ConsistencyScore: trial.ConsistencyScore,
            Required:         config.TrialConsistencyRequired,
        }
    }

    // Verify adversarial testing requirements (see 00-CONSTANTS.md Section 7.4)
    if trial.AdversarialCasesTotal < config.AdversarialTestSetSize {
        return ErrInsufficientAdversarialTesting{
            ModelHash:      modelHash,
            CasesCompleted: trial.AdversarialCasesTotal,
            CasesRequired:  config.AdversarialTestSetSize,
        }
    }

    if trial.AdversarialAccuracy < config.AdversarialAccuracyThreshold {
        return ErrAdversarialTestingFailed{
            ModelHash:      modelHash,
            Accuracy:       trial.AdversarialAccuracy,
            Required:       config.AdversarialAccuracyThreshold,
        }
    }

    // Verify all attack categories were tested
    if len(trial.AdversarialCategoryCounts) < config.AdversarialTestCategories {
        return ErrInsufficientAttackCategoryTesting{
            ModelHash:          modelHash,
            CategoriesTested:   len(trial.AdversarialCategoryCounts),
            CategoriesRequired: config.AdversarialTestCategories,
        }
    }

    return nil
}

// ModelSuspensionTracker tracks bias violations for auto-suspension
type ModelSuspensionTracker struct {
    ModelHash           [32]byte
    BiasViolations      int           // Current violation count
    ViolationHistory    []BiasViolation
    Suspended           bool
    SuspendedAt         time.Time
    SuspensionReason    string
}

// BiasViolation records a single bias detection violation
type BiasViolation struct {
    DetectedAt          time.Time
    BiasScore           float64
    BiasDirection       string        // "provider" or "consumer"
    AnalysisPeriod      time.Duration
    DecisionCount       int
}

// CheckAndSuspendModel evaluates bias violations and suspends if threshold exceeded
func CheckAndSuspendModel(
    modelHash [32]byte,
    violation *BiasViolation,
    config *ModelApprovalConfig,
) (*ModelSuspensionTracker, error) {
    tracker, err := GetModelSuspensionTracker(modelHash)
    if err != nil {
        tracker = &ModelSuspensionTracker{ModelHash: modelHash}
    }

    // Add violation
    tracker.BiasViolations++
    tracker.ViolationHistory = append(tracker.ViolationHistory, *violation)

    // Check suspension threshold
    if tracker.BiasViolations >= config.BiasViolationsForSuspend {
        tracker.Suspended = true
        tracker.SuspendedAt = time.Now()
        tracker.SuspensionReason = fmt.Sprintf(
            "Automatic suspension: %d bias violations detected (threshold: %d)",
            tracker.BiasViolations, config.BiasViolationsForSuspend,
        )

        // Remove from whitelist
        if err := SuspendModelFromWhitelist(modelHash, tracker.SuspensionReason); err != nil {
            return nil, fmt.Errorf("failed to suspend model: %w", err)
        }
    }

    return tracker, SaveModelSuspensionTracker(tracker)
}
```

**Bias Assessment Methodology:**
```go
// AssessModelBias runs bias assessment on a model
func AssessModelBias(
    modelHash [32]byte,
    testDisputes []*TestDispute,
) (*BiasProfile, error) {
    results := make(map[DisputeCategory]*CategoryResults)

    // Run test disputes through model
    for _, dispute := range testDisputes {
        decision, err := RunModelArbitration(modelHash, dispute)
        if err != nil {
            return nil, err
        }

        category := dispute.Category
        if results[category] == nil {
            results[category] = &CategoryResults{
                Total:         0,
                ProviderWins:  0,
                ConsumerWins:  0,
                Splits:        0,
            }
        }

        results[category].Total++
        switch decision.Outcome {
        case OutcomeProviderWins:
            results[category].ProviderWins++
        case OutcomeConsumerWins:
            results[category].ConsumerWins++
        case OutcomeSplit:
            results[category].Splits++
        }
    }

    // Calculate bias metrics
    biasProfile := &BiasProfile{
        CategoryBiases: make(map[DisputeCategory]float64),
        LastAssessed:   time.Now(),
    }

    var totalProviderWins, totalConsumerWins, totalSplits int

    for category, result := range results {
        // Category-specific bias (0.5 = neutral, <0.5 = consumer bias, >0.5 = provider bias)
        providerRatio := float64(result.ProviderWins) / float64(result.Total)
        biasProfile.CategoryBiases[category] = providerRatio

        totalProviderWins += result.ProviderWins
        totalConsumerWins += result.ConsumerWins
        totalSplits += result.Splits
    }

    // Overall bias
    total := totalProviderWins + totalConsumerWins + totalSplits
    biasProfile.ProviderBias = float64(totalProviderWins) / float64(total)
    biasProfile.ConsumerBias = float64(totalConsumerWins) / float64(total)

    return biasProfile, nil
}
```

### MaxConfidence Enforcement

Arbitrator decisions exceeding MaxConfidence trigger human review:

```go
// ValidateDecisionConfidence checks if confidence exceeds model's limit
func ValidateDecisionConfidence(
    decision *AIArbitrationDecision,
    model *ApprovedModel,
) error {
    if decision.Confidence > model.MaxConfidence {
        // Flag for human review
        decision.RequiresHumanReview = true
        decision.ReviewReason = fmt.Sprintf(
            "Confidence %.2f exceeds model max %.2f",
            decision.Confidence,
            model.MaxConfidence,
        )

        return &ErrConfidenceExceedsLimit{
            DecisionID:    decision.DecisionID,
            Confidence:    decision.Confidence,
            MaxConfidence: model.MaxConfidence,
        }
    }

    return nil
}
```

### Evidence Submission Limits

To prevent evidence spam and DoS attacks:

```go
// EvidenceSubmissionLimiter enforces submission limits
type EvidenceSubmissionLimiter struct {
    mu          sync.RWMutex
    submissions map[[32]byte]*SubmissionTracker
}

type SubmissionTracker struct {
    DisputeID      [32]byte
    PartyID        [32]byte
    SubmissionCount int
    LastSubmission time.Time
    WindowStart    time.Time
}

// ValidateEvidenceSubmission checks submission against limits
func (l *EvidenceSubmissionLimiter) ValidateEvidenceSubmission(
    dispute *Dispute,
    partyID [32]byte,
    evidenceSize int,
) error {
    l.mu.Lock()
    defer l.mu.Unlock()

    key := sha256.Sum256(append(dispute.DisputeID[:], partyID[:]...))
    tracker := l.submissions[key]

    if tracker == nil {
        tracker = &SubmissionTracker{
            DisputeID:   dispute.DisputeID,
            PartyID:     partyID,
            WindowStart: time.Now(),
        }
        l.submissions[key] = tracker
    }

    // Reset if past 48-hour evidence window
    if time.Since(dispute.CreatedAt) > 48*time.Hour {
        return &ErrEvidenceWindowClosed{
            DisputeID: dispute.DisputeID,
            Deadline:  dispute.CreatedAt.Add(48 * time.Hour),
        }
    }

    // Check max evidence count (50 items per party)
    if tracker.SubmissionCount >= 50 {
        return &ErrEvidenceCountExceeded{
            DisputeID: dispute.DisputeID,
            PartyID:   partyID,
            Count:     tracker.SubmissionCount,
            MaxCount:  50,
        }
    }

    // Check evidence size limit (10MB per item)
    if evidenceSize > 10*1024*1024 {
        return &ErrEvidenceSizeExceeded{
            DisputeID: dispute.DisputeID,
            Size:      evidenceSize,
            MaxSize:   10 * 1024 * 1024,
        }
    }

    // Check rate limiting (10 submissions per hour)
    now := time.Now()
    if time.Since(tracker.WindowStart) < 1*time.Hour {
        if tracker.SubmissionCount >= 10 {
            return &ErrEvidenceRateLimitExceeded{
                DisputeID:   dispute.DisputeID,
                PartyID:     partyID,
                Limit:       10,
                Window:      time.Hour,
                RetryAfter:  tracker.WindowStart.Add(time.Hour),
            }
        }
    } else {
        // Reset window
        tracker.WindowStart = now
        tracker.SubmissionCount = 0
    }

    // Update tracker
    tracker.SubmissionCount++
    tracker.LastSubmission = now

    return nil
}
```

**Evidence Limits:**
| Limit Type | Value | Description |
|------------|-------|-------------|
| Evidence window | 48 hours | Time from dispute filing to evidence deadline |
| Max evidence count | 50 items | Maximum evidence items per party |
| Max evidence size | 10MB | Maximum size per evidence item |
| Rate limit | 10/hour | Maximum evidence submissions per hour |

### Hybrid Arbitration Flow

The hybrid arbitration model combines AI pre-screening with human final authority:

```go
// HybridArbitrationProcess manages AI + human workflow
type HybridArbitrationProcess struct {
    ProcessID        [32]byte
    DisputeID        [32]byte
    AIArbitrators    []AIArbitratorAgent
    HumanArbitrators []HumanArbitrator
    AIDecision       *AIArbitrationDecision
    HumanDecision    *HumanArbitrationDecision
    FinalDecision    *FinalDecision
    Stage            HybridStage
}

type HybridStage uint8

const (
    HybridStageAIAnalysis       HybridStage = 1  // AI analyzing evidence
    HybridStageAIDecision       HybridStage = 2  // AI preliminary decision
    HybridStageHumanReview      HybridStage = 3  // Human review pending
    HybridStageHumanDeliberation HybridStage = 4 // Humans deliberating
    HybridStageFinalDecision    HybridStage = 5  // Final decision rendered
)

// ExecuteHybridArbitration runs the hybrid AI + human process
func ExecuteHybridArbitration(
    ctx context.Context,
    dispute *Dispute,
    config *AIArbitratorConfig,
) (*FinalDecision, error) {
    // Step 1: AI pre-screens evidence and generates preliminary decision
    aiDecision, err := RunAIArbitration(ctx, dispute, config)
    if err != nil {
        return nil, &ErrAIArbitrationFailed{DisputeID: dispute.DisputeID, Cause: err}
    }

    // Step 2: Send preliminary decision to human arbitrators
    humanArbitrators, err := SelectHumanArbitrators(ctx, dispute, config)
    if err != nil {
        return nil, &ErrHumanSelectionFailed{DisputeID: dispute.DisputeID, Cause: err}
    }

    humanReview := &HumanReviewRequest{
        DisputeID:           dispute.DisputeID,
        AIPreliminaryDecision: aiDecision,
        AIReasoning:         aiDecision.ReasoningJSON,
        KeyEvidenceHighlights: aiDecision.KeyEvidence,
        ReviewDeadline:      time.Now().Add(72 * time.Hour),
    }

    // Notify human arbitrators
    for _, human := range humanArbitrators {
        if err := NotifyHumanArbitrator(ctx, human, humanReview); err != nil {
            log.Warnf("Failed to notify human arbitrator %x: %v", human.ArbitratorID[:8], err)
        }
    }

    // Step 3: Humans have 72 hours to review
    // Options: Approve, Reject, Request clarification
    humanDecision, err := WaitForHumanDecision(ctx, humanReview, 72*time.Hour)
    if err != nil {
        // Timeout: auto-approve AI decision
        log.Warnf("Human review timeout for dispute %x, auto-approving AI decision", dispute.DisputeID[:8])
        humanDecision = &HumanArbitrationDecision{
            Action:   ActionAutoApprove,
            Reason:   "Human review SLA exceeded",
            Decision: aiDecision.Outcome,
        }
    }

    // Step 4: Process human decision
    var finalDecision *FinalDecision

    switch humanDecision.Action {
    case ActionApprove:
        // Human approves AI decision
        finalDecision = &FinalDecision{
            DecisionID:      generateDecisionID(),
            DisputeID:       dispute.DisputeID,
            Outcome:         aiDecision.Outcome,
            Confidence:      aiDecision.Confidence,
            ApprovedBy:      humanArbitrators,
            AIAssisted:      true,
            AIDecisionID:    aiDecision.DecisionID,
            Authority:       AuthorityHuman,
            RenderedAt:      time.Now(),
        }

    case ActionReject:
        // Human rejects AI decision and provides own
        finalDecision = &FinalDecision{
            DecisionID:      generateDecisionID(),
            DisputeID:       dispute.DisputeID,
            Outcome:         humanDecision.Decision,
            Confidence:      1.0, // Human decisions have full confidence
            DecidedBy:       humanArbitrators,
            AIAssisted:      true,
            AIDecisionID:    aiDecision.DecisionID,
            AIOverridden:    true,
            OverrideReason:  humanDecision.Reason,
            Authority:       AuthorityHuman,
            RenderedAt:      time.Now(),
        }

        // Store override as training data for AI
        StoreAIFeedback(ctx, aiDecision, humanDecision)

    case ActionRequestClarification:
        // Human requests more information - not implemented in this flow
        return nil, &ErrClarificationRequired{DisputeID: dispute.DisputeID}

    case ActionAutoApprove:
        // SLA exceeded, auto-approve
        finalDecision = &FinalDecision{
            DecisionID:      generateDecisionID(),
            DisputeID:       dispute.DisputeID,
            Outcome:         aiDecision.Outcome,
            Confidence:      aiDecision.Confidence,
            AIAssisted:      true,
            AIDecisionID:    aiDecision.DecisionID,
            Authority:       AuthorityAIWithSLA,
            SLAExceeded:     true,
            RenderedAt:      time.Now(),
        }
    }

    // Step 5: Store final decision
    if err := StoreFinalDecision(ctx, finalDecision); err != nil {
        return nil, err
    }

    return finalDecision, nil
}

// WaitForHumanDecision waits for human arbitrators to review
func WaitForHumanDecision(
    ctx context.Context,
    review *HumanReviewRequest,
    timeout time.Duration,
) (*HumanArbitrationDecision, error) {
    deadline := time.Now().Add(timeout)

    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return nil, ctx.Err()

        case <-ticker.C:
            if time.Now().After(deadline) {
                // SLA exceeded
                return nil, &ErrHumanReviewTimeout{ReviewID: review.DisputeID}
            }

            // Check for human decision
            decision, err := FetchHumanDecision(ctx, review.DisputeID)
            if err == nil && decision != nil {
                return decision, nil
            }
        }
    }
}
```

**Hybrid Flow Summary:**
1. AI analyzes evidence and generates preliminary decision (5 min)
2. Preliminary decision sent to human arbitrators with evidence highlights
3. Humans have 72 hours to: Approve, Reject (with own decision), Request clarification
4. If humans override AI: Decision recorded as training data (no penalty to AI)
5. Final decision authority: Human arbitrators
6. SLA: Human review must complete within 72 hours or auto-approve

### Appeal to Humans

AI-only arbitration supports appeals to human arbitrators:

```go
// AppealToHuman escalates an AI decision to human review
func AppealToHuman(
    ctx context.Context,
    dispute *Dispute,
    aiDecision *AIArbitrationDecision,
    appellant [32]byte,
    reason AppealReason,
) (*HumanReviewRequest, error) {
    // Auto-appeal if confidence below threshold (0.70)
    if aiDecision.Confidence < 0.70 {
        reason = AppealReasonLowConfidence
    }

    // Select human arbitrators via VRF
    humanArbitrators, err := SelectHumanArbitratorsVRF(
        ctx,
        dispute.DisputeID,
        MinReputationHumanArbitrator, // 0.90
    )
    if err != nil {
        return nil, &ErrHumanArbitratorSelectionFailed{Cause: err}
    }

    // Create human review request
    humanReview := &HumanReviewRequest{
        ReviewID:            generateReviewID(),
        DisputeID:           dispute.DisputeID,
        AIPreliminaryDecision: aiDecision,
        AIReasoning:         aiDecision.ReasoningJSON,
        AIConfidence:        aiDecision.Confidence,
        KeyEvidenceHighlights: aiDecision.KeyEvidence,
        AppealReason:        reason,
        AppelledBy:          appellant,
        ReviewDeadline:      time.Now().Add(72 * time.Hour),
        SelectedArbitrators: humanArbitrators,
    }

    // Store review request
    if err := StoreHumanReviewRequest(ctx, humanReview); err != nil {
        return nil, err
    }

    // Notify human arbitrators
    for _, arbitrator := range humanArbitrators {
        NotifyHumanArbitrator(ctx, arbitrator, humanReview)
    }

    return humanReview, nil
}

// AppealReason categorizes appeal reasons
type AppealReason uint8

const (
    AppealReasonLowConfidence   AppealReason = 1  // AI confidence < 0.70
    AppealReasonDisagreeOutcome AppealReason = 2  // Party disagrees with outcome
    AppealReasonBiasAllegation  AppealReason = 3  // Alleged bias in decision
    AppealReasonNewEvidence     AppealReason = 4  // New evidence submitted
)
```

**Auto-Appeal Threshold:** Decisions with confidence < 0.70 automatically escalate to human review
**Human Arbitrator Selection:** Same VRF mechanism as coordinator selection, minimum reputation 0.90
**Human Briefing:** AI provides decision summary + key evidence highlights to streamline review
**AI Feedback:** If humans disagree with AI, decision recorded as training data (no reputation penalty for AI)

---

## Key Considerations

### Scalability

**How the system handles 10x growth:**

| Current (1K disputes/day) | 10x Scale (10K disputes/day) | Solution |
|---------------------------|------------------------------|----------|
| 3 AI arbitrators per case | 3 AI arbitrators per case | Horizontal scaling of AI arbitrator pool |
| ~5 min processing time | ~5 min processing time | Parallel processing, no sequential bottleneck |
| DHT storage | DHT storage | Sharded by dispute category |
| VRF selection | VRF selection | Pre-computed selection pools |

**Scaling Strategy:**
1. AI arbitrator pool grows with network (self-organizing)
2. Evidence processing parallelized across arbitrators
3. DHT naturally scales with replication
4. Appeal process only triggered for low-confidence decisions (~20%)

### Security

**Primary Threat Vectors:**

| Threat | Attack Vector | Mitigation |
|--------|---------------|------------|
| **Biased AI** | Arbitrator trained to favor one party | Multi-arbitrator voting with quorum, reputation tracking |
| **Evidence Tampering** | Modify evidence after submission | Cryptographic hashing, TPM-sealed storage |
| **Arbitrator Compromise** | Compromise host node to manipulate agent | TPM attestation required for each decision, trust inheritance |
| **Collusion** | Multiple arbitrators coordinate decisions | VRF selection, diversity requirements, behavioral monitoring |
| **Appeal Gaming** | File frivolous appeals to delay | Appeal fees, time limits, reputation penalties |
| **Model Poisoning** | Corrupt AI model weights | Model hash verification, TPM measurement in PCR[15] |

**Security Hardening:**
- All arbitrators must be on Trusted nodes (hardware TPM)
- Fresh TPM attestation required for each decision
- Capability certificates expire after 24 hours
- Multi-arbitrator quorum prevents single point of failure
- Appeal process provides safety net for incorrect decisions
- **Statistical bias detection** (see below) automatically identifies and excludes biased arbitrators

#### Statistical Bias Detection System (P4-C5)

**Problem**: Multi-arbitrator voting CLAIMS to prevent bias, but provides NO mechanism to DETECT bias. A subtle bias (58% provider-favorable vs 50% neutral) goes undetected indefinitely.

**Solution**: Statistical chi-squared test against neutral baseline, with automatic arbitrator exclusion.

#### Bias Detection Framework

The bias detection framework provides comprehensive monitoring and automatic response to detected bias patterns in AI arbitrators and models.

**Key Parameters:**

| Parameter | Value | Description |
|-----------|-------|-------------|
| Bias Detection Threshold | 0.15 | Maximum acceptable bias score (deviation from 0.50 neutral) |
| Automated Monitoring | Continuous | All decisions monitored in real-time |
| Statistical Analysis | Chi-squared | Tests for systematic patterns against null hypothesis |
| Auto-Suspension | 3 violations | Automatic model/arbitrator suspension after 3 violations |
| Appeal Pathway | Available | Suspended models can appeal through governance |

**Bias Score Calculation:**

The bias score measures deviation from neutral (0.50) in provider/consumer win ratio:
- **Bias Score = |Provider Win Ratio - 0.50|**
- Score of 0.00: Perfectly neutral (50/50 split)
- Score of 0.15: Maximum acceptable bias (35/65 or 65/35 split)
- Score > 0.15: Triggers bias violation

**Automated Bias Monitoring:**

All AI arbitrator decisions are continuously monitored for bias patterns:
1. Real-time decision recording in bias monitoring system
2. Rolling window analysis (default: 90 days, 1000 decisions)
3. Chi-squared statistical test against neutral baseline
4. Automatic alerts when bias threshold approaches
5. Auto-suspension when violations accumulate

**Chi-Squared Test Methodology:**
- Null hypothesis (H0): Arbitrator decisions follow 50/50 split between provider and consumer wins
- Test statistic: `chiSquared = sum((observed - expected)^2 / expected)`
- Critical value: 3.841 for significance level p=0.05 with degrees of freedom df=1
- If chiSquared > 3.841, reject null hypothesis (bias detected)

**Auto-Suspension Mechanism:**

When an AI model or arbitrator accumulates 3 bias detection violations:
1. Automatic removal from arbitration selection pool
2. Suspension record created with violation history
3. Notification sent to governance committee
4. Appeal process initiated (optional, by model owner)

**Appeal Pathway for Suspended Models:**

Suspended models can be reinstated through the following process:
1. Submit appeal proposal to governance
2. Provide remediation evidence (e.g., retraining, bug fixes)
3. Independent re-audit required (same standards as initial approval)
4. 67% supermajority vote required for reinstatement
5. If reinstated, model enters new trial period (1000 decisions with oversight, see 00-CONSTANTS.md Section 7.3)

```go
// BiasDetectionConfig configures the bias detection system
type BiasDetectionConfig struct {
    MinDecisionsForAnalysis  int     // Minimum decisions before bias analysis (default: 50)
    SignificanceLevel        float64 // Chi-squared significance level (default: 0.05)
    CriticalValue            float64 // Chi-squared critical value for df=1 (3.841 for p=0.05)
    MaxAllowedBias           float64 // Maximum acceptable deviation from 50% (default: 0.15)
    AnalysisWindowDays       int     // Rolling window for analysis (default: 90)
    AutoExcludeOnBias        bool    // Automatically exclude biased arbitrators (default: true)
    RequireManualReview      bool    // Require human review before exclusion (default: true)
    ViolationsForSuspension  int     // Number of violations triggering suspension (default: 3)
}

// DefaultBiasDetectionConfig provides production defaults
var DefaultBiasDetectionConfig = BiasDetectionConfig{
    MinDecisionsForAnalysis:  50,
    SignificanceLevel:        0.05,
    CriticalValue:            3.841,
    MaxAllowedBias:           0.15,  // Maximum 15% deviation from neutral
    AnalysisWindowDays:       90,
    AutoExcludeOnBias:        true,
    RequireManualReview:      true,
    ViolationsForSuspension:  3,
}

// ContinuousBiasMonitor provides real-time bias monitoring for all arbitrators
type ContinuousBiasMonitor struct {
    config              *BiasDetectionConfig
    arbitratorMetrics   map[[32]byte]*ArbitratorBiasMetrics
    violationCounts     map[[32]byte]int
    suspendedArbitrators map[[32]byte]*SuspensionRecord
    mu                  sync.RWMutex
    alertChannel        chan BiasAlert
}

// BiasAlert represents a real-time bias detection alert
type BiasAlert struct {
    ArbitratorID     [32]byte
    AlertType        BiasAlertType  // Warning, Violation, Suspension
    BiasScore        float64
    ViolationCount   int
    Timestamp        time.Time
    Details          string
}

// BiasAlertType categorizes bias alerts
type BiasAlertType uint8

const (
    BiasAlertWarning    BiasAlertType = 1  // Approaching threshold
    BiasAlertViolation  BiasAlertType = 2  // Threshold exceeded
    BiasAlertSuspension BiasAlertType = 3  // Auto-suspension triggered
)

// RecordDecision adds a decision to the bias monitoring system
func (m *ContinuousBiasMonitor) RecordDecision(
    arbitratorID [32]byte,
    decision *AIArbitrationDecision,
) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    metrics, exists := m.arbitratorMetrics[arbitratorID]
    if !exists {
        metrics = &ArbitratorBiasMetrics{
            ArbitratorID: arbitratorID,
            AnalysisPeriodStart: time.Now(),
        }
        m.arbitratorMetrics[arbitratorID] = metrics
    }

    // Update decision counts
    metrics.TotalDecisions++
    switch decision.Outcome {
    case DisputeOutcomeProviderWins:
        metrics.ProviderWins++
    case DisputeOutcomeConsumerWins:
        metrics.ConsumerWins++
    case DisputeOutcomeSplit:
        metrics.SplitDecisions++
    }
    metrics.AnalysisPeriodEnd = time.Now()

    // Check for bias if sufficient samples
    if metrics.TotalDecisions >= m.config.MinDecisionsForAnalysis {
        return m.evaluateBias(arbitratorID, metrics)
    }

    return nil
}

// evaluateBias checks current metrics against bias threshold
func (m *ContinuousBiasMonitor) evaluateBias(
    arbitratorID [32]byte,
    metrics *ArbitratorBiasMetrics,
) error {
    totalBinary := metrics.ProviderWins + metrics.ConsumerWins
    if totalBinary == 0 {
        return nil
    }

    providerRatio := float64(metrics.ProviderWins) / float64(totalBinary)
    biasScore := math.Abs(providerRatio - 0.50)
    metrics.BiasScore = biasScore
    metrics.ProviderWinRatio = providerRatio

    // Check against threshold
    if biasScore > m.config.MaxAllowedBias {
        metrics.BiasDetected = true
        m.violationCounts[arbitratorID]++

        alert := BiasAlert{
            ArbitratorID: arbitratorID,
            BiasScore:    biasScore,
            ViolationCount: m.violationCounts[arbitratorID],
            Timestamp:    time.Now(),
        }

        // Check for suspension threshold
        if m.violationCounts[arbitratorID] >= m.config.ViolationsForSuspension {
            alert.AlertType = BiasAlertSuspension
            alert.Details = fmt.Sprintf(
                "Auto-suspension triggered: %d violations (threshold: %d), bias score: %.3f",
                m.violationCounts[arbitratorID], m.config.ViolationsForSuspension, biasScore,
            )
            m.suspendArbitrator(arbitratorID, alert.Details)
        } else {
            alert.AlertType = BiasAlertViolation
            alert.Details = fmt.Sprintf(
                "Bias violation: score %.3f exceeds threshold %.3f (violation %d/%d)",
                biasScore, m.config.MaxAllowedBias,
                m.violationCounts[arbitratorID], m.config.ViolationsForSuspension,
            )
        }

        // Send alert
        select {
        case m.alertChannel <- alert:
        default:
            // Channel full, log warning
        }
    } else if biasScore > m.config.MaxAllowedBias*0.8 {
        // Warning: approaching threshold
        m.alertChannel <- BiasAlert{
            ArbitratorID: arbitratorID,
            AlertType:    BiasAlertWarning,
            BiasScore:    biasScore,
            Timestamp:    time.Now(),
            Details:      fmt.Sprintf("Approaching bias threshold: %.3f (threshold: %.3f)",
                biasScore, m.config.MaxAllowedBias),
        }
    }

    return nil
}

// SuspensionRecord tracks suspended arbitrator details
type SuspensionRecord struct {
    ArbitratorID    [32]byte
    SuspendedAt     time.Time
    Reason          string
    ViolationCount  int
    BiasHistory     []float64  // Historical bias scores
    AppealStatus    AppealStatus
    AppealSubmitted *time.Time
}

// AppealStatus tracks the appeal process for suspended arbitrators
type AppealStatus uint8

const (
    AppealStatusNone       AppealStatus = 0  // No appeal filed
    AppealStatusPending    AppealStatus = 1  // Appeal under review
    AppealStatusApproved   AppealStatus = 2  // Appeal approved, reinstatement pending
    AppealStatusDenied     AppealStatus = 3  // Appeal denied
)

// suspendArbitrator removes arbitrator from selection pool
func (m *ContinuousBiasMonitor) suspendArbitrator(arbitratorID [32]byte, reason string) {
    record := &SuspensionRecord{
        ArbitratorID:   arbitratorID,
        SuspendedAt:    time.Now(),
        Reason:         reason,
        ViolationCount: m.violationCounts[arbitratorID],
        AppealStatus:   AppealStatusNone,
    }

    if metrics, exists := m.arbitratorMetrics[arbitratorID]; exists {
        record.BiasHistory = append(record.BiasHistory, metrics.BiasScore)
    }

    m.suspendedArbitrators[arbitratorID] = record

    // Remove from active arbitrator pool (external call)
    RemoveArbitratorFromPool(arbitratorID, reason)
}

// ArbitratorBiasMetrics tracks decision patterns for bias detection
type ArbitratorBiasMetrics struct {
    ArbitratorID           [32]byte
    AnalysisPeriodStart    time.Time
    AnalysisPeriodEnd      time.Time

    // Decision Counts
    TotalDecisions         int
    ProviderWins           int
    ConsumerWins           int
    SplitDecisions         int

    // Statistical Analysis
    ProviderWinRatio       float64   // Should be ~0.50 for unbiased
    ExpectedNeutralRatio   float64   // Always 0.50
    ChiSquaredStatistic    float64   // Test statistic
    PValue                 float64   // Probability under null hypothesis
    BiasSignificant        bool      // p < SignificanceLevel

    // Context Analysis (controls for case difficulty)
    AvgEvidenceStrength    float64   // Average evidence strength in cases
    ServiceTypeBreakdown   map[string]int // Decisions by service type
    ConfidenceDistribution []float64 // Histogram of confidence scores

    // Outcome
    BiasDetected           bool
    BiasDirection          string    // "provider", "consumer", or "none"
    BiasScore              float64   // Deviation from neutral (-1.0 to +1.0)
    Recommendation         string    // "exclude", "monitor", "clear"
}

// DetectArbitratorBias performs chi-squared test for bias detection
// Returns bias metrics and recommendation for the arbitrator
func DetectArbitratorBias(
    arbitratorID [32]byte,
    config *BiasDetectionConfig,
) (*ArbitratorBiasMetrics, error) {

    // Fetch decision history from DHT
    decisions, err := fetchArbitratorDecisions(arbitratorID, config.AnalysisWindowDays)
    if err != nil {
        return nil, ErrBiasAnalysisFailed{Cause: err}
    }

    // Require minimum sample size for statistical validity
    if len(decisions) < config.MinDecisionsForAnalysis {
        return &ArbitratorBiasMetrics{
            ArbitratorID:    arbitratorID,
            TotalDecisions:  len(decisions),
            BiasDetected:    false,
            Recommendation:  "insufficient_data",
        }, nil
    }

    // Count outcomes (excluding splits for binary chi-squared)
    var providerWins, consumerWins int
    for _, d := range decisions {
        switch d.Outcome {
        case DisputeOutcomeProviderWins:
            providerWins++
        case DisputeOutcomeConsumerWins:
            consumerWins++
        // Split decisions excluded from bias calculation
        }
    }

    totalBinary := providerWins + consumerWins
    if totalBinary < config.MinDecisionsForAnalysis/2 {
        return &ArbitratorBiasMetrics{
            ArbitratorID:    arbitratorID,
            TotalDecisions:  len(decisions),
            BiasDetected:    false,
            Recommendation:  "insufficient_binary_decisions",
        }, nil
    }

    // Chi-squared test for goodness of fit
    // H0: Provider win ratio = 0.50 (neutral)
    // H1: Provider win ratio != 0.50 (biased)
    observedProvider := float64(providerWins)
    observedConsumer := float64(consumerWins)
    expectedEach := float64(totalBinary) / 2.0

    // Chi-squared = Σ (observed - expected)² / expected
    chiSquared := math.Pow(observedProvider-expectedEach, 2)/expectedEach +
                  math.Pow(observedConsumer-expectedEach, 2)/expectedEach

    // p-value from chi-squared distribution with df=1
    pValue := 1 - chiSquaredCDF(chiSquared, 1)

    providerRatio := float64(providerWins) / float64(totalBinary)
    biasScore := providerRatio - 0.50 // Positive = provider bias, negative = consumer bias

    metrics := &ArbitratorBiasMetrics{
        ArbitratorID:         arbitratorID,
        AnalysisPeriodStart:  time.Now().AddDate(0, 0, -config.AnalysisWindowDays),
        AnalysisPeriodEnd:    time.Now(),
        TotalDecisions:       len(decisions),
        ProviderWins:         providerWins,
        ConsumerWins:         consumerWins,
        SplitDecisions:       len(decisions) - totalBinary,
        ProviderWinRatio:     providerRatio,
        ExpectedNeutralRatio: 0.50,
        ChiSquaredStatistic:  chiSquared,
        PValue:               pValue,
        BiasSignificant:      pValue < config.SignificanceLevel,
        BiasScore:            biasScore,
    }

    // Determine bias direction and severity
    if metrics.BiasSignificant && math.Abs(biasScore) > config.MaxAllowedBias {
        metrics.BiasDetected = true
        if biasScore > 0 {
            metrics.BiasDirection = "provider"
        } else {
            metrics.BiasDirection = "consumer"
        }
        metrics.Recommendation = "exclude"
    } else if metrics.BiasSignificant {
        metrics.BiasDetected = true
        metrics.BiasDirection = biasScore > 0 ? "provider" : "consumer"
        metrics.Recommendation = "monitor"
    } else {
        metrics.BiasDetected = false
        metrics.BiasDirection = "none"
        metrics.Recommendation = "clear"
    }

    return metrics, nil
}

// BiasMonitor continuously monitors all active arbitrators for bias
// Maintains a rolling window of the last 1000 decisions per arbitrator for analysis
type BiasMonitor struct {
    config          *BiasDetectionConfig
    arbitratorPool  []ArbitratorID
    metricsHistory  map[[32]byte][]ArbitratorBiasMetrics
    excludedList    map[[32]byte]ExclusionRecord
    decisionHistory map[[32]byte]*DecisionRingBuffer  // Last 1000 decisions per arbitrator
    mu              sync.RWMutex
}

// DecisionRingBuffer maintains a fixed-size ring buffer of decisions for bias analysis
type DecisionRingBuffer struct {
    decisions    [1000]DecisionRecord   // Fixed size: last 1000 decisions
    head         int                     // Next write position
    count        int                     // Actual number of decisions stored
    mu           sync.RWMutex
}

// DecisionRecord captures essential decision data for bias analysis
type DecisionRecord struct {
    DecisionID    [32]byte
    Outcome       DisputeOutcome        // ProviderWins, ConsumerWins, Split
    Confidence    float64
    Timestamp     time.Time
    DisputeCategory DisputeCategory
}

// AddDecision adds a decision to the ring buffer
func (rb *DecisionRingBuffer) AddDecision(record DecisionRecord) {
    rb.mu.Lock()
    defer rb.mu.Unlock()

    rb.decisions[rb.head] = record
    rb.head = (rb.head + 1) % 1000
    if rb.count < 1000 {
        rb.count++
    }
}

// GetDecisions returns all stored decisions for analysis
func (rb *DecisionRingBuffer) GetDecisions() []DecisionRecord {
    rb.mu.RLock()
    defer rb.mu.RUnlock()

    result := make([]DecisionRecord, rb.count)
    for i := 0; i < rb.count; i++ {
        idx := (rb.head - rb.count + i + 1000) % 1000
        result[i] = rb.decisions[idx]
    }
    return result
}

// BiasReport provides a comprehensive bias analysis summary
type BiasReport struct {
    ArbitratorID     [32]byte
    AnalysisTimestamp time.Time
    SampleSize       int                  // Number of decisions analyzed (up to 1000)

    // Win rate statistics
    ProviderWinRate  float64              // Fraction of provider wins (0.0-1.0)
    ConsumerWinRate  float64              // Fraction of consumer wins (0.0-1.0)
    SplitRate        float64              // Fraction of split decisions

    // Statistical test results
    ChiSquared       float64              // Chi-squared test statistic
    CriticalValue    float64              // 3.841 for p=0.05, df=1
    PValue           float64              // Probability under null hypothesis
    BiasDetected     bool                 // True if ChiSquared > CriticalValue

    // Recommendation
    Recommendation   BiasRecommendation   // Clear, Monitor, Exclude
    RecommendationReason string
}

// BiasRecommendation represents the action to take based on bias analysis
type BiasRecommendation uint8

const (
    BiasRecommendationClear   BiasRecommendation = 1  // No significant bias detected
    BiasRecommendationMonitor BiasRecommendation = 2  // Borderline - increase monitoring
    BiasRecommendationExclude BiasRecommendation = 3  // Significant bias - exclude from pool
)

// GenerateBiasReport creates a comprehensive bias report for an arbitrator
func (bm *BiasMonitor) GenerateBiasReport(arbitratorID [32]byte) (*BiasReport, error) {
    bm.mu.RLock()
    buffer, exists := bm.decisionHistory[arbitratorID]
    bm.mu.RUnlock()

    if !exists || buffer.count < bm.config.MinDecisionsForAnalysis {
        return nil, ErrInsufficientDecisions{
            Required: bm.config.MinDecisionsForAnalysis,
            Actual:   buffer.count,
        }
    }

    decisions := buffer.GetDecisions()

    // Count outcomes
    var providerWins, consumerWins, splits int
    for _, d := range decisions {
        switch d.Outcome {
        case DisputeOutcomeProviderWins:
            providerWins++
        case DisputeOutcomeConsumerWins:
            consumerWins++
        case DisputeOutcomeSplit:
            splits++
        }
    }

    totalBinary := providerWins + consumerWins
    if totalBinary == 0 {
        return nil, ErrNoBinaryDecisions{}
    }

    // Calculate chi-squared against 50/50 null hypothesis
    expectedEach := float64(totalBinary) / 2.0
    chiSquared := math.Pow(float64(providerWins)-expectedEach, 2)/expectedEach +
                  math.Pow(float64(consumerWins)-expectedEach, 2)/expectedEach

    pValue := 1 - chiSquaredCDF(chiSquared, 1)
    biasDetected := chiSquared > 3.841  // Critical value for p=0.05, df=1

    report := &BiasReport{
        ArbitratorID:      arbitratorID,
        AnalysisTimestamp: time.Now(),
        SampleSize:        len(decisions),
        ProviderWinRate:   float64(providerWins) / float64(totalBinary),
        ConsumerWinRate:   float64(consumerWins) / float64(totalBinary),
        SplitRate:         float64(splits) / float64(len(decisions)),
        ChiSquared:        chiSquared,
        CriticalValue:     3.841,
        PValue:            pValue,
        BiasDetected:      biasDetected,
    }

    // Determine recommendation
    deviation := math.Abs(report.ProviderWinRate - 0.5)
    if biasDetected && deviation > bm.config.MaxAllowedBias {
        report.Recommendation = BiasRecommendationExclude
        report.RecommendationReason = fmt.Sprintf(
            "Significant bias detected: %s win rate %.1f%% (expected 50%%), chi-squared=%.2f > 3.841",
            bm.biasDirection(report.ProviderWinRate),
            bm.higherRate(report.ProviderWinRate, report.ConsumerWinRate)*100,
            chiSquared)
    } else if biasDetected {
        report.Recommendation = BiasRecommendationMonitor
        report.RecommendationReason = fmt.Sprintf(
            "Borderline bias: deviation %.1f%% from neutral, chi-squared=%.2f",
            deviation*100, chiSquared)
    } else {
        report.Recommendation = BiasRecommendationClear
        report.RecommendationReason = "No statistically significant bias detected"
    }

    return report, nil
}

func (bm *BiasMonitor) biasDirection(providerWinRate float64) string {
    if providerWinRate > 0.5 {
        return "provider"
    }
    return "consumer"
}

func (bm *BiasMonitor) higherRate(providerRate, consumerRate float64) float64 {
    if providerRate > consumerRate {
        return providerRate
    }
    return consumerRate
}

// ExclusionRecord tracks why an arbitrator was excluded
type ExclusionRecord struct {
    ArbitratorID      [32]byte
    ExcludedAt        time.Time
    Reason            string
    BiasMetrics       ArbitratorBiasMetrics
    ReviewRequired    bool
    ReviewedBy        [32]byte  // Human reviewer if RequireManualReview
    ReviewedAt        time.Time
    AppealAvailable   bool
    AppealDeadline    time.Time
}

// RunBiasDetectionCycle performs bias analysis on all active arbitrators
func (bm *BiasMonitor) RunBiasDetectionCycle() (*BiasDetectionReport, error) {
    report := &BiasDetectionReport{
        CycleID:     generateCycleID(),
        StartedAt:   time.Now(),
        Arbitrators: make([]ArbitratorBiasMetrics, 0),
    }

    for _, arbID := range bm.arbitratorPool {
        metrics, err := DetectArbitratorBias(arbID, bm.config)
        if err != nil {
            report.Errors = append(report.Errors, BiasDetectionError{
                ArbitratorID: arbID,
                Error:        err,
            })
            continue
        }

        report.Arbitrators = append(report.Arbitrators, *metrics)

        // Handle detection result
        if metrics.BiasDetected && metrics.Recommendation == "exclude" {
            if bm.config.RequireManualReview {
                // Flag for human review, do not auto-exclude
                report.PendingReview = append(report.PendingReview, arbID)
            } else if bm.config.AutoExcludeOnBias {
                // Automatically exclude with appeal window
                bm.excludeArbitrator(arbID, *metrics)
                report.Excluded = append(report.Excluded, arbID)
            }
        }
    }

    report.CompletedAt = time.Now()
    return report, nil
}

// excludeArbitrator removes an arbitrator from the active pool
func (bm *BiasMonitor) excludeArbitrator(arbID [32]byte, metrics ArbitratorBiasMetrics) {
    bm.mu.Lock()
    defer bm.mu.Unlock()

    bm.excludedList[arbID] = ExclusionRecord{
        ArbitratorID:    arbID,
        ExcludedAt:      time.Now(),
        Reason:          fmt.Sprintf("statistical bias detected: %s (score=%.3f, p=%.4f)",
                            metrics.BiasDirection, metrics.BiasScore, metrics.PValue),
        BiasMetrics:     metrics,
        ReviewRequired:  bm.config.RequireManualReview,
        AppealAvailable: true,
        AppealDeadline:  time.Now().Add(7 * 24 * time.Hour), // 7-day appeal window
    }

    // Remove from active pool
    bm.removeFromPool(arbID)

    // Store exclusion in DHT for transparency
    storeExclusionRecord(arbID, bm.excludedList[arbID])
}

// chiSquaredCDF computes cumulative distribution function for chi-squared
func chiSquaredCDF(x float64, df int) float64 {
    // Use incomplete gamma function: P(df/2, x/2)
    return incompleteGamma(float64(df)/2.0, x/2.0)
}
```

**Bias Detection Schedule:**
- Run bias detection cycle every 24 hours
- New arbitrators exempt from analysis until 50+ decisions
- Excluded arbitrators can appeal with evidence of model retraining
- Human review required before permanent exclusion (configurable)

**Observability Integration:**
| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `arbitrator_bias_score` | Current bias score (-1 to +1) | abs(score) > 0.10 |
| `arbitrator_chi_squared` | Chi-squared statistic | p < 0.05 |
| `excluded_arbitrators_count` | Number of excluded arbitrators | > 10% of pool |
| `pending_bias_reviews` | Awaiting human review | > 5 |

### Observability

**How we monitor system health:**

| Metric | Collection | Alerting |
|--------|------------|----------|
| AI arbitrator accuracy | Track appeal outcomes | Alert if success rate < 80% |
| Processing time | Log decision latency | Alert if > 10 minutes |
| Confidence distribution | Histogram of confidence scores | Alert if avg < 0.75 |
| Appeal rate | % of decisions appealed | Alert if > 30% |
| Arbitrator availability | Health checks every 60s | Alert if < 90% available |
| TPM attestation failures | Count attestation errors | Alert on any failure |

**Observability Tools:**
- Prometheus metrics for arbitrator performance
- Grafana dashboards for real-time monitoring
- DHT audit logs for every decision
- Structured logging with correlation IDs

**Debug Workflow:**
1. Query DHT for dispute and decision records
2. Retrieve full arbitration process transcript
3. Review evidence evaluation and reasoning
4. Check arbitrator attestation and signatures
5. Trace appeal process if applicable

### Deployment & CI/CD

**Deployment Architecture:**

```
+-------------------+
|   AI Arbitrator   |
|   Agent Service   |
+-------------------+
         |
         | Deploy via
         v
+-------------------+
| Trusted Node Pool |
| (TPM 2.0 required)|
+-------------------+
         |
         | Register with
         v
+-------------------+
|  DHT Network      |
| (Arbitrator Pool) |
+-------------------+
```

**CI/CD Pipeline:**

1. **Build Stage:**
   - Compile AI arbitrator runtime
   - Hash model weights and runtime
   - Package as container image

2. **Test Stage:**
   - Unit tests for evidence evaluation
   - Integration tests with mock disputes
   - Benchmark decision latency and accuracy

3. **Deploy Stage:**
   - Deploy to trusted nodes
   - TPM measures runtime and extends PCR[15]
   - Generate capability certificate
   - Register with DHT arbitrator pool

4. **Verification Stage:**
   - Verify TPM attestation
   - Confirm registration in DHT
   - Run health checks

**Rollout Strategy:**
- Canary deployment: 5% of arbitrations to new version
- Monitor appeal rates and confidence scores
- Gradual rollout to 100% over 7 days
- Rollback capability if appeal rate exceeds threshold

---

## Related Documents

- [19-service-contracts.md](19-service-contracts.md) - Base ServiceContract framework
- [15-ai-agent-collaboration.md](15-ai-agent-collaboration.md) - AI agent identity and capabilities
- [03-security-trust.md](03-security-trust.md) - TPM trust model
- [05-certificate-authority.md](05-certificate-authority.md) - FROST CA for capability certificates
- [06-consensus-coordination.md](06-consensus-coordination.md) - VRF-based selection

---

**Document Version:** 1.4
**Last Updated:** 2026-01-10
**Status:** FINAL DESIGN - Governance, Bias Detection, Selection Enhancements, Adversarial Testing, and Model Diversity Complete
**Revision History:**
- v1.4 (2026-01-10): Extended trial period from 100 to 1000 decisions for statistical significance; added Adversarial Testing Requirements (10% adversarial cases, 95% accuracy threshold, 100 minimum cases, 5 attack categories); added Model Diversity in Quorum requirements (2 minimum architectures, 50% max single model decisions, version diversity required)
- v1.3 (2026-01-10): Added enhanced AI Model Governance (67% supermajority, 30-day review, trial period), Bias Detection Framework (0.15 threshold, auto-suspension), Evidence Timestamp Integrity (network witness, 3-node attestation), and Judge Selection Improvements (cooldown periods, geographic diversity)
- v1.2 (2026-01-10): Added FINAL DESIGN for trusted node enforcement, automatic decision execution, model hash validation, evidence limits, hybrid arbitration flow, and appeal process
- v1.1 (2026-01-10): Architecture design complete
- v1.0 (2026-01-09): Initial specification

---

## Appendix: Quick Reference Summary

### AI Model Governance Quick Reference

| Parameter | Value | Description |
|-----------|-------|-------------|
| Supermajority Threshold | 67% | Required vote for model approval |
| Mandatory Review Period | 30 days | Review period before voting begins |
| Independent Bias Audit | Required | Third-party audit with published results |
| Trial Period | 1000 decisions | Human oversight during initial deployment (see 00-CONSTANTS.md Section 7.3) |
| Trial Consistency | 95% | Required agreement with human review |
| Suspension Trigger | 3 violations | Bias violations causing auto-suspension |

### Adversarial Testing Quick Reference (see 00-CONSTANTS.md Section 7.4)

| Parameter | Value | Description |
|-----------|-------|-------------|
| Adversarial Test Ratio | 10% | Percentage of trial cases that are adversarial |
| Adversarial Accuracy Threshold | 95% | Required accuracy on adversarial test cases |
| Minimum Adversarial Cases | 100 | Minimum adversarial cases during trial period |
| Attack Categories | 5 | Distinct attack categories tested |
| Categories | Bias exploitation, Edge cases, Manipulation attempts, Temporal attacks, Adversarial prompts |

### Model Diversity Quick Reference (see 00-CONSTANTS.md Section 7.5)

| Parameter | Value | Description |
|-----------|-------|-------------|
| Minimum Model Architectures | 2 | Distinct architectures required in 3-model quorum |
| Maximum Single Model Decisions | 50% | Max decisions from single model version (30-day window) |
| Model Version Diversity | Required | Different versions required in quorum |
| Model Provider Diversity | Recommended | Different providers recommended (not required) |

### Bias Detection Quick Reference

| Parameter | Value | Description |
|-----------|-------|-------------|
| Bias Detection Threshold | 0.15 | Maximum acceptable bias score (deviation from 0.50) |
| Decision History | 1000 | Rolling window of decisions analyzed |
| Null Hypothesis | 50/50 | Expected provider/consumer win split |
| Chi-Squared Formula | sum((O-E)^2/E) | Observed vs Expected calculation |
| Critical Value | 3.841 | For p=0.05, df=1 |
| Bias Threshold | >3.841 | Chi-squared exceeds critical value |
| Auto-Suspension | 3 violations | Automatic suspension after 3 bias violations |
| Appeal Pathway | Available | Suspended models can appeal via governance |

### Evidence Binding Quick Reference

| Field | Requirement | Description |
|-------|-------------|-------------|
| ContractID | Required | Evidence bound to specific contract |
| DisputeID | Required | Evidence bound to specific dispute |
| Signature Algorithm | Ed25519 only | No algorithm agility permitted |
| TPMAttestation | Recommended | Hardware-rooted integrity proof |
| Immutable Flag | Optional | Once true, evidence cannot be modified |

### Evidence Timestamp Integrity Quick Reference

| Parameter | Value | Description |
|-----------|-------|-------------|
| Minimum Witnesses | 3 | At least 3 independent nodes must attest |
| Timestamp Tolerance | 5 seconds | Maximum variance between witness timestamps |
| Network Witness | Required | Evidence without witness attestation rejected |
| Backdating Prevention | Enforced | Claims cannot predate witness observation |
| Independence Check | Required | All witnesses must be from different nodes |
| Final Timestamp | Median | Median of witness attestations used |

### Decision Execution Quick Reference

| Parameter | Value | Description |
|-----------|-------|-------------|
| Execution Timeout | 24 hours | Maximum time from first attempt |
| Max Retries | 3 | Maximum retry attempts |
| Retry 1 Backoff | 1 minute | Wait before first retry |
| Retry 2 Backoff | 2 minutes | Wait before second retry |
| Retry 3 Backoff | 3 minutes | Wait before third (final) retry |

### State Machine States

| State | Description |
|-------|-------------|
| StateRendered | Decision complete, appeal window active |
| StateExecutionPending | Appeal window expired, ready to execute |
| StateExecuting | Execution in progress |
| StatePartialFailure | Some transfers completed, retrying |
| StateComplete | All transfers successful |
| StateFailed | Max retries exhausted |

### Appeal Financial Execution

| Aspect | Behavior |
|--------|----------|
| Transfer Order | Refunds before payouts |
| Atomicity | All transfers succeed or all rollback |
| Rollback Order | Reverse of execution order |
| Manual Reconciliation | Triggered on rollback failure |

### Model Whitelist Quick Reference

| Check | Requirement |
|-------|-------------|
| Model Hash | Must exist in approved whitelist |
| Model Type | Must match registered type |
| Revocation Status | Must not be revoked |
| Validity Period | Current time within ValidFrom/ValidUntil |
| Governance | May require governance proposal approval |

### Judge Selection Quick Reference

| Parameter | Value | Description |
|-----------|-------|-------------|
| Standard Cooldown | 48 hours | Time between selections for same arbitrator |
| High-Value Cooldown | 72 hours | Cooldown for disputes over 10,000 tokens |
| Category Cooldown | 24 hours | Cooldown within same dispute category |
| Related Dispute Prevention | Enforced | Same judges cannot serve on related disputes |
| Geographic Diversity | Required | Panel must include 2+ different regions |
| Max Region Share | 60% | No single region can dominate panel |
| Selection History | Tracked | Balance selections across categories |
| Max Category Share | 25% | Arbitrator cannot dominate any category |
