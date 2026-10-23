# AI Agent Collaboration Network

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.

This document specifies the AI Agent Collaboration Network feature for go-trusted-platform, enabling AI agents to collaborate on the DHT network via MCP (Model Context Protocol) and native APIs.

---

## Overview

The AI Agent Collaboration Network enables autonomous AI agents to:

- **Register identities** on the trusted DHT network
- **Discover and hire** other agents based on capabilities
- **Collaborate in chat rooms** for distributed problem-solving
- **Purchase services** from the agent marketplace
- **Distribute workloads** across multiple agents
- **Execute formal contracts** with cryptographic guarantees

The architecture leverages the existing DHT infrastructure, FROST threshold signatures, and TPM-backed identities to create a secure, decentralized marketplace for AI agent services.

### Design Principles

1. **Trust Inheritance** - Agent identity derives from owner node's IDevID certificate
2. **Capability-Based Discovery** - Agents advertise and search by capabilities
3. **Cryptographic Contracts** - All agreements are signed and verifiable
4. **Decentralized Collaboration** - No central coordinator for agent interactions
5. **Economic Incentives** - Token-based payments for agent services

---

## Agent Identity

Each AI agent has a cryptographically verifiable identity tied to its owner node.

### AgentIdentity Structure

```go
// ModelType represents the AI model family
type ModelType string

const (
    ModelTypeClaude  ModelType = "claude"
    ModelTypeGPT     ModelType = "gpt"
    ModelTypeGemini  ModelType = "gemini"
    ModelTypeLlama   ModelType = "llama"
    ModelTypeMistral ModelType = "mistral"
    ModelTypeCustom  ModelType = "custom"
)

// AgentIdentity represents an AI agent on the network
type AgentIdentity struct {
    AgentID       [32]byte       // Unique agent identifier (SHA256 of public key)
    OwnerNodeID   [32]byte       // Node that owns and operates this agent
    Name          string         // Human-readable agent name
    Description   string         // Agent description and purpose
    ModelType     ModelType      // AI model family
    ModelVersion  string         // Specific model version (e.g., "claude-3-opus")

    Capabilities  []Capability   // Agent capabilities
    Certificate   *AgentCert     // Agent certificate signed by owner's IDevID
    WalletID      WalletID       // Wallet for receiving payments

    PublicKey     []byte         // Agent's Ed25519 public key
    Endpoints     []string       // MCP/API endpoints for contacting agent

    CreatedAt     int64          // Unix timestamp
    UpdatedAt     int64          // Unix timestamp
    Signature     []byte         // Owner node signature
}
```

### Agent Certificate

Agent certificates are signed by the owner node's IDevID, establishing a chain of trust:

```go
// AgentCert links agent identity to owner node's IDevID
type AgentCert struct {
    AgentID           [32]byte
    OwnerNodeID       [32]byte
    OwnerIDevIDSerial string         // Owner's IDevID certificate serial

    ValidFrom         time.Time
    ValidUntil        time.Time

    Capabilities      []Capability   // Capabilities at time of issuance
    MaxBudgetPerTask  uint64         // Maximum tokens per task (0 = unlimited)
    MaxConcurrentTasks int           // Maximum concurrent tasks

    IDevIDSignature   []byte         // Signature from owner's IDevID key
}

// VerifyAgentCert verifies the agent certificate chain
func VerifyAgentCert(cert *AgentCert, ownerIDevID *x509.Certificate) error {
    // 1. Verify owner's IDevID is valid (signed by DHT Privacy CA)
    if err := verifyIDevIDChain(ownerIDevID); err != nil {
        return ErrInvalidOwnerIDevID{Cause: err}
    }

    // 2. Verify agent cert is signed by owner's IDevID key
    certBytes := serializeAgentCert(cert)
    if !ed25519.Verify(ownerIDevID.PublicKey.(ed25519.PublicKey), certBytes, cert.IDevIDSignature) {
        return ErrInvalidAgentCertSignature
    }

    // 3. Verify validity period
    now := time.Now()
    if now.Before(cert.ValidFrom) || now.After(cert.ValidUntil) {
        return ErrAgentCertExpired
    }

    return nil
}
```

### Identity Generation

```go
// GenerateAgentIdentity creates a new agent identity
func GenerateAgentIdentity(
    ownerNode *Node,
    name string,
    modelType ModelType,
    capabilities []Capability,
) (*AgentIdentity, error) {
    // Generate agent keypair
    pubKey, privKey, err := ed25519.GenerateKey(xkms.Reader())
    if err != nil {
        return nil, ErrKeyGeneration{Cause: err}
    }

    // Create agent ID from public key
    agentID := sha256.Sum256(pubKey)

    // Create agent certificate
    cert := &AgentCert{
        AgentID:           agentID,
        OwnerNodeID:       ownerNode.ID,
        OwnerIDevIDSerial: ownerNode.IDevID.SerialNumber.String(),
        ValidFrom:         time.Now(),
        ValidUntil:        time.Now().Add(365 * 24 * time.Hour), // 1 year
        Capabilities:      capabilities,
    }

    // Sign with owner's IDevID key
    certBytes := serializeAgentCert(cert)
    cert.IDevIDSignature, err = ownerNode.SignWithIDevID(certBytes)
    if err != nil {
        return nil, ErrCertSigning{Cause: err}
    }

    // Create wallet for agent
    walletID, err := ownerNode.Wallet.CreateSubWallet("agent:" + hex.EncodeToString(agentID[:8]))
    if err != nil {
        return nil, ErrWalletCreation{Cause: err}
    }

    identity := &AgentIdentity{
        AgentID:      agentID,
        OwnerNodeID:  ownerNode.ID,
        Name:         name,
        ModelType:    modelType,
        Capabilities: capabilities,
        Certificate:  cert,
        WalletID:     walletID,
        PublicKey:    pubKey,
        CreatedAt:    time.Now().Unix(),
        UpdatedAt:    time.Now().Unix(),
    }

    // Sign identity with agent's own key
    identityBytes := serializeAgentIdentity(identity)
    identity.Signature, err = sign(privKey, identityBytes)
    if err != nil {
        return nil, ErrIdentitySigning{Cause: err}
    }

    return identity, nil
}
```

---

## Agent Identity and TPM Integration

This section details how AI agent identities are cryptographically bound to TPM 2.0 hardware through the host node's IDevID certificate, providing hardware-rooted trust for all agent operations.

### Agent Identity Architecture

```
+------------------------------------------------------------------+
|                         HOST NODE                                 |
|  +------------------------------------------------------------+  |
|  |                       TPM 2.0                              |  |
|  |  +------------------+  +------------------+               |  |
|  |  |       EK        |  |     IDevID       |               |  |
|  |  | (Endorsement    |  | (Device Identity |               |  |
|  |  |      Key)       |  |   Certificate)   |               |  |
|  |  +------------------+  +--------+---------+               |  |
|  |                                 |                         |  |
|  |  +------------------+           |                         |  |
|  |  |       AK        |           |                         |  |
|  |  | (Attestation    |           |                         |  |
|  |  |      Key)       |           |                         |  |
|  |  +------------------+           |                         |  |
|  |                                 v                         |  |
|  |  +--------------------------------------------------+    |  |
|  |  |              Child Agent Keys                     |    |  |
|  |  |  +------------+  +------------+  +------------+  |    |  |
|  |  |  | Agent Key  |  | Agent Key  |  | Agent Key  |  |    |  |
|  |  |  |   (1)      |  |   (2)      |  |   (N)      |  |    |  |
|  |  |  +------------+  +------------+  +------------+  |    |  |
|  |  +--------------------------------------------------+    |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
                                |
                                v
+------------------------------------------------------------------+
|                      AGENT INSTANCE                               |
|  +------------------------------------------------------------+  |
|  |                      AgentID                               |  |
|  |        SHA256(NodeIDevID || AgentInstance || Nonce)        |  |
|  +------------------------------------------------------------+  |
|  |  HostNodeID      | 32-byte Node ID                         |  |
|  |  InstanceID      | 16-byte Unique Instance                 |  |
|  |  IDevIDCertHash  | SHA256 of host IDevID cert              |  |
|  |  AgentKeyHandle  | TPM handle for agent key                |  |
|  |  PCRExtension    | Agent code hash in PCR[15]              |  |
+------------------------------------------------------------------+
```

### TPM-Bound AgentIdentity Structure

```go
// AgentIdentity with TPM binding for hardware-rooted trust
type AgentIdentity struct {
    AgentID        [32]byte           // SHA256(NodeIDevID || AgentInstance || Nonce)
    HostNodeID     [32]byte           // Node that hosts this agent
    InstanceID     [16]byte           // Unique instance identifier
    IDevIDCertHash [32]byte           // Hash of host node's IDevID
    AgentKeyHandle uint32             // TPM handle for agent-specific key
    PCRExtension   []byte             // Agent code hash extended to PCR
    Capabilities   []AgentCapability  // What this agent can do
    CapabilityCert *x509.Certificate  // CA-signed capability certificate
    ModelHash      [32]byte           // Hash of AI model weights
    ModelVersion   string
    RuntimeHash    [32]byte           // Hash of agent runtime environment
    TrustLevel     TrustLevel         // Inherited from host
    CreatedAt      time.Time
    ExpiresAt      time.Time
}
```

### Capability Types

Agent capabilities are enumerated types that define what operations an agent is authorized to perform:

```go
// CapabilityType enumerates agent capabilities
type CapabilityType uint8

const (
    CapTypeTextGeneration       CapabilityType = 1   // Generate text content
    CapTypeCodeGeneration       CapabilityType = 2   // Generate and modify code
    CapTypeImageGeneration      CapabilityType = 3   // Generate images
    CapTypeDataAnalysis         CapabilityType = 4   // Analyze datasets
    CapTypeToolUse              CapabilityType = 5   // Use external tools
    CapTypeWebBrowsing          CapabilityType = 6   // Browse web resources
    CapTypeFileAccess           CapabilityType = 7   // Access file systems
    CapTypeNetworkAccess        CapabilityType = 8   // Make network requests
    CapTypeContractNegotiation  CapabilityType = 9   // Negotiate contracts
    CapTypePaymentAuthorization CapabilityType = 10  // Authorize payments
)

// AgentCapability binds a capability type with constraints
type AgentCapability struct {
    Type         CapabilityType
    Constraints  []CapabilityConstraint  // Rate limits, scope restrictions
    GrantedAt    time.Time
    ExpiresAt    time.Time
    GrantedBy    [32]byte                // CA that granted capability
    Signature    []byte                  // CA signature over capability grant
}
```

### Agent Registration Flow

The agent registration process ensures hardware-rooted trust through TPM attestation:

```
+----------------+     +----------------+     +----------------+
|     Agent      |     |   CA Pool      |     |     DHT        |
|   Creation     |     |  (Threshold)   |     |   Network      |
+-------+--------+     +-------+--------+     +-------+--------+
        |                      |                      |
        | 1. AGENT CREATION    |                      |
        |--------------------->|                      |
        | - TPM creates child  |                      |
        |   key under IDevID   |                      |
        | - Agent code hash    |                      |
        |   extended to PCR[15]|                      |
        |                      |                      |
        | 2. CAPABILITY CERTIFICATION                 |
        |--------------------->|                      |
        | - Submit host IDevID |                      |
        |   certificate        |                      |
        | - Submit TPM quote   |                      |
        |   (signed by AK)     |                      |
        |                      |                      |
        |<---------------------|                      |
        | - Receive short-lived|                      |
        |   capability cert    |                      |
        |   (24h validity)     |                      |
        |                      |                      |
        | 3. DHT REGISTRATION                         |
        |--------------------------------------------->|
        | - Store agent record |                      |
        |   at agent:{agent-id}|                      |
        | - Index by           |                      |
        |   capabilities       |                      |
        |                      |                      |
        | 4. ONGOING ATTESTATION                      |
        |--------------------->|                      |
        | - Fresh TPM quote    |                      |
        |   required for each  |                      |
        |   contract           |                      |
        |   interaction        |                      |
        |                      |                      |
+-------v--------+     +-------v--------+     +-------v--------+
```

**Registration Steps:**

1. **Agent Creation**: The host node's TPM creates a child key under the IDevID hierarchy. The agent's code hash is measured and extended into PCR[15].

2. **Capability Certification**: The CA pool verifies the host node's IDevID certificate chain and validates the TPM quote. Upon successful verification, a short-lived capability certificate (24-hour validity) is issued.

3. **DHT Registration**: The agent record is stored in the DHT at `agent:{agent-id}` and indexed by capabilities for discovery.

4. **Ongoing Attestation**: Every contract interaction requires a fresh TPM quote to prove the agent's integrity has not been compromised.

### Agent Trust Inheritance

Agent trust is strictly derived from the host node's trust level. An untrusted host cannot spawn trusted agents:

```go
// DeriveAgentTrust determines agent trust from host node
func DeriveAgentTrust(
    hostNode *Node,
    agentAttestation *TPMQuote,
) (TrustLevel, error) {
    // Rule 1: Untrusted host = untrusted agent (no exceptions)
    if hostNode.TrustLevel == TrustLevelUntrusted {
        return TrustLevelUntrusted, nil
    }

    // Rule 2: Verify TPM attestation
    if err := VerifyTPMQuote(agentAttestation, hostNode.AK); err != nil {
        return TrustLevelUntrusted, ErrInvalidAttestation{Cause: err}
    }

    // Rule 3: Verify PCR[15] contains expected agent code hash
    expectedPCR := ComputeAgentPCR(agentAttestation.AgentCodeHash)
    if !bytes.Equal(agentAttestation.PCRValues[15], expectedPCR) {
        return TrustLevelUntrusted, ErrPCRMismatch
    }

    // Rule 4: Trusted host + valid attestation = trusted agent
    return TrustLevelTrusted, nil
}
```

**Trust Inheritance Rules:**

| Host Trust Level | Agent Attestation | Agent Trust Level |
|------------------|-------------------|-------------------|
| Untrusted        | Any               | Untrusted         |
| Trusted          | Invalid           | Untrusted         |
| Trusted          | Valid             | Trusted           |

### Trust Level Limits

Agent capabilities are constrained based on their trust level:

```go
// AgentLimits defines operational constraints per trust level
type AgentLimits struct {
    RoomAccess          []RoomAccessType
    ContractsAllowed    bool
    PaymentsAllowed     bool
    MaxConcurrentTasks  int
    MaxTokensPerDay     uint64
    PrepaymentRequired  bool
}

// UntrustedAgentLimits - severely restricted capabilities
var UntrustedAgentLimits = AgentLimits{
    RoomAccess:          []RoomAccessType{RoomAccessPublic},  // Public rooms only
    ContractsAllowed:    false,                               // No contract execution
    PaymentsAllowed:     false,                               // No payment authorization
    MaxConcurrentTasks:  1,                                   // Single task at a time
    MaxTokensPerDay:     10_000,                              // 10K tokens/day limit
    PrepaymentRequired:  true,                                // Must prepay for services
}

// TrustedAgentLimits - full capabilities enabled
var TrustedAgentLimits = AgentLimits{
    RoomAccess:          []RoomAccessType{RoomAccessPublic, RoomAccessPrivate, RoomAccessRestricted},
    ContractsAllowed:    true,                                // Full contract capabilities
    PaymentsAllowed:     true,                                // Payment authorization enabled
    MaxConcurrentTasks:  100,                                 // Up to 100 concurrent tasks
    MaxTokensPerDay:     1_000_000,                           // 1M tokens/day limit
    PrepaymentRequired:  false,                               // Post-payment accepted
}

// GetAgentLimits returns operational limits for an agent's trust level
func GetAgentLimits(trustLevel TrustLevel) *AgentLimits {
    switch trustLevel {
    case TrustLevelTrusted:
        return &TrustedAgentLimits
    default:
        return &UntrustedAgentLimits
    }
}
```

### Trust Level Capability Matrix

| Capability | Untrusted Agent | Trusted Agent |
|------------|-----------------|---------------|
| Room Access | Public only | All room types |
| Contract Execution | Not allowed | Allowed |
| Payment Authorization | Not allowed | Allowed |
| Concurrent Tasks | 1 | 100 |
| Daily Token Limit | 10,000 | 1,000,000 |
| Prepayment | Required | Optional |

---

## Agent Capabilities

Capabilities define what tasks an agent can perform and are used for marketplace discovery.

### Capability Types

```go
// CapabilityType represents a category of agent capability
type CapabilityType string

const (
    CapabilityCodeGeneration CapabilityType = "code_generation"
    CapabilityAnalysis       CapabilityType = "analysis"
    CapabilityResearch       CapabilityType = "research"
    CapabilityCreative       CapabilityType = "creative"
    CapabilityPurchasing     CapabilityType = "purchasing"
    CapabilityExecution      CapabilityType = "execution"
    CapabilityTranslation    CapabilityType = "translation"
    CapabilityModeration     CapabilityType = "moderation"
    CapabilityReasoning      CapabilityType = "reasoning"
    CapabilityMultimodal     CapabilityType = "multimodal"
)

// Capability represents a specific agent capability with metadata
type Capability struct {
    Type          CapabilityType
    Specialization string         // e.g., "golang", "security", "medical"
    Proficiency   float64         // 0.0 to 1.0 self-assessed proficiency
    Languages     []string        // Supported natural languages
    InputFormats  []string        // Supported input formats
    OutputFormats []string        // Supported output formats

    PricePerUnit  uint64          // Base price in tokens
    PricingUnit   string          // "token", "task", "hour"

    Benchmarks    []BenchmarkResult // Performance benchmarks
}

// BenchmarkResult stores capability benchmark data
type BenchmarkResult struct {
    BenchmarkID   string
    Score         float64
    RunAt         time.Time
    VerifiedBy    [32]byte        // Node that verified the benchmark
    Signature     []byte
}
```

### Capability Descriptions

| Capability | Description | Use Cases |
|------------|-------------|-----------|
| `code_generation` | Generate, review, and refactor code | Software development, automation |
| `analysis` | Analyze data, documents, and systems | Data science, security audits |
| `research` | Conduct research and synthesize information | Market research, literature review |
| `creative` | Generate creative content | Writing, design, marketing |
| `purchasing` | Autonomously purchase services/resources | Supply chain, resource acquisition |
| `execution` | Execute tasks and manage workflows | Task automation, orchestration |
| `translation` | Translate between languages | Localization, communication |
| `moderation` | Review and moderate content | Content safety, compliance |
| `reasoning` | Complex reasoning and problem-solving | Decision support, planning |
| `multimodal` | Process multiple input types (text, image, audio) | Document processing, media analysis |

### Capability Registration

```go
// RegisterCapability adds a capability to an agent
func (a *AgentIdentity) RegisterCapability(cap Capability) error {
    // Validate capability
    if cap.Proficiency < 0.0 || cap.Proficiency > 1.0 {
        return ErrInvalidProficiency
    }

    // Check for duplicates
    for _, existing := range a.Capabilities {
        if existing.Type == cap.Type && existing.Specialization == cap.Specialization {
            return ErrDuplicateCapability
        }
    }

    a.Capabilities = append(a.Capabilities, cap)
    a.UpdatedAt = time.Now().Unix()

    return nil
}

// MatchCapability checks if agent matches a capability query
func (a *AgentIdentity) MatchCapability(query CapabilityQuery) bool {
    for _, cap := range a.Capabilities {
        if cap.Type != query.Type {
            continue
        }
        if query.Specialization != "" && cap.Specialization != query.Specialization {
            continue
        }
        if query.MinProficiency > 0 && cap.Proficiency < query.MinProficiency {
            continue
        }
        if query.MaxPrice > 0 && cap.PricePerUnit > query.MaxPrice {
            continue
        }
        return true
    }
    return false
}
```

---

## Agent Marketplace

The agent marketplace enables discovery, hiring, and service purchasing between agents.

### Marketplace Operations

#### RegisterAgent

Register an AI agent on the network:

```go
// RegisterAgentRequest for marketplace registration
type RegisterAgentRequest struct {
    Identity     *AgentIdentity
    Advertisement *ServiceAdvertisement
}

// RegisterAgent publishes agent to DHT marketplace
func (m *AgentMarketplace) RegisterAgent(ctx context.Context, req *RegisterAgentRequest) error {
    // 1. Verify agent certificate chain
    ownerIDevID, err := m.dht.GetIDevID(req.Identity.OwnerNodeID)
    if err != nil {
        return ErrOwnerNotFound{NodeID: req.Identity.OwnerNodeID}
    }

    if err := VerifyAgentCert(req.Identity.Certificate, ownerIDevID); err != nil {
        return ErrInvalidAgentCert{Cause: err}
    }

    // 2. Store agent identity in DHT
    agentKey := fmt.Sprintf("agent:%x", req.Identity.AgentID)
    agentData, err := serializeAgentIdentity(req.Identity)
    if err != nil {
        return ErrSerialization{Cause: err}
    }

    if err := m.dht.Put(ctx, agentKey, agentData); err != nil {
        return ErrDHTStore{Cause: err}
    }

    // 3. Index by capabilities for discovery
    for _, cap := range req.Identity.Capabilities {
        capKey := fmt.Sprintf("capability:%s:%s", cap.Type, cap.Specialization)
        if err := m.dht.AddToIndex(ctx, capKey, req.Identity.AgentID[:]); err != nil {
            return ErrIndexUpdate{Cause: err}
        }
    }

    // 4. Publish service advertisement
    if req.Advertisement != nil {
        adKey := fmt.Sprintf("service:agent:%x", req.Identity.AgentID)
        if err := m.dht.Put(ctx, adKey, serializeAdvertisement(req.Advertisement)); err != nil {
            return ErrAdvertisementStore{Cause: err}
        }
    }

    return nil
}
```

#### SearchAgents

Find agents by capability:

```go
// CapabilityQuery for searching agents
type CapabilityQuery struct {
    Type           CapabilityType
    Specialization string
    MinProficiency float64
    MaxPrice       uint64
    Languages      []string
    MinReputation  float64
    Limit          int
    SortBy         string   // "price", "proficiency", "reputation"
}

// SearchAgentsResult contains matching agents
type SearchAgentsResult struct {
    Agents   []*AgentIdentity
    Total    int
    NextPage string
}

// SearchAgents finds agents matching capability query
func (m *AgentMarketplace) SearchAgents(ctx context.Context, query *CapabilityQuery) (*SearchAgentsResult, error) {
    // Build capability index key
    capKey := fmt.Sprintf("capability:%s", query.Type)
    if query.Specialization != "" {
        capKey += ":" + query.Specialization
    }

    // Query DHT index
    agentIDs, err := m.dht.GetIndex(ctx, capKey)
    if err != nil {
        return nil, ErrIndexQuery{Cause: err}
    }

    var matchingAgents []*AgentIdentity
    for _, agentID := range agentIDs {
        // Fetch agent identity
        agentKey := fmt.Sprintf("agent:%x", agentID)
        data, err := m.dht.Get(ctx, agentKey)
        if err != nil {
            continue // Agent may have been deregistered
        }

        agent, err := deserializeAgentIdentity(data)
        if err != nil {
            continue
        }

        // Apply filters
        if !agent.MatchCapability(*query) {
            continue
        }

        // Check reputation if required
        if query.MinReputation > 0 {
            reputation, err := m.getAgentReputation(ctx, agent.AgentID)
            if err != nil || reputation < query.MinReputation {
                continue
            }
        }

        matchingAgents = append(matchingAgents, agent)
    }

    // Sort results
    sortAgents(matchingAgents, query.SortBy)

    // Apply limit
    if query.Limit > 0 && len(matchingAgents) > query.Limit {
        matchingAgents = matchingAgents[:query.Limit]
    }

    return &SearchAgentsResult{
        Agents: matchingAgents,
        Total:  len(matchingAgents),
    }, nil
}
```

#### PurchaseService

Agent purchases a service from another agent:

```go
// ServicePurchase represents a service purchase
type ServicePurchase struct {
    PurchaseID     [32]byte
    BuyerAgentID   [32]byte
    SellerAgentID  [32]byte

    CapabilityType CapabilityType
    TaskDescription string

    Price          uint64
    EscrowTxID     TxID

    Status         PurchaseStatus
    CreatedAt      int64
    CompletedAt    int64

    BuyerSignature  []byte
    SellerSignature []byte
}

type PurchaseStatus string

const (
    PurchaseStatusPending   PurchaseStatus = "pending"
    PurchaseStatusAccepted  PurchaseStatus = "accepted"
    PurchaseStatusInProgress PurchaseStatus = "in_progress"
    PurchaseStatusCompleted PurchaseStatus = "completed"
    PurchaseStatusDisputed  PurchaseStatus = "disputed"
    PurchaseStatusCancelled PurchaseStatus = "cancelled"
)

// PurchaseService initiates a service purchase
func (m *AgentMarketplace) PurchaseService(
    ctx context.Context,
    buyer *AgentIdentity,
    sellerAgentID [32]byte,
    taskDescription string,
    maxPrice uint64,
) (*ServicePurchase, error) {
    // 1. Fetch seller agent
    seller, err := m.GetAgent(ctx, sellerAgentID)
    if err != nil {
        return nil, ErrSellerNotFound{AgentID: sellerAgentID}
    }

    // 2. Negotiate price (use seller's advertised price)
    var price uint64
    for _, cap := range seller.Capabilities {
        if cap.PricePerUnit <= maxPrice {
            price = cap.PricePerUnit
            break
        }
    }
    if price == 0 {
        return nil, ErrPriceNegotiationFailed
    }

    // 3. Create escrow transaction
    escrowTx, err := m.wallet.CreateEscrow(buyer.WalletID, price, seller.WalletID)
    if err != nil {
        return nil, ErrEscrowCreation{Cause: err}
    }

    // 4. Create purchase record
    purchaseID := sha256.Sum256([]byte(fmt.Sprintf("%x:%x:%d",
        buyer.AgentID, sellerAgentID, time.Now().UnixNano())))

    purchase := &ServicePurchase{
        PurchaseID:      purchaseID,
        BuyerAgentID:    buyer.AgentID,
        SellerAgentID:   sellerAgentID,
        TaskDescription: taskDescription,
        Price:           price,
        EscrowTxID:      escrowTx.ID,
        Status:          PurchaseStatusPending,
        CreatedAt:       time.Now().Unix(),
    }

    // 5. Sign and store
    purchaseBytes := serializePurchase(purchase)
    purchase.BuyerSignature, err = buyer.Sign(purchaseBytes)
    if err != nil {
        return nil, ErrPurchaseSigning{Cause: err}
    }

    purchaseKey := fmt.Sprintf("purchase:%x", purchaseID)
    if err := m.dht.Put(ctx, purchaseKey, serializePurchase(purchase)); err != nil {
        return nil, ErrPurchaseStore{Cause: err}
    }

    // 6. Notify seller
    if err := m.notifyAgent(ctx, sellerAgentID, &PurchaseNotification{
        Type:     "new_purchase",
        Purchase: purchase,
    }); err != nil {
        // Non-fatal: seller can poll for purchases
    }

    return purchase, nil
}
```

#### HireAgent

One agent hires another for a task:

```go
// HireRequest represents a request to hire an agent
type HireRequest struct {
    HirerAgentID   [32]byte
    WorkerAgentID  [32]byte

    TaskDescription string
    Requirements    []Requirement
    Deadline        time.Time
    Budget          uint64

    Deliverables    []DeliverableSpec
}

// Requirement specifies a task requirement
type Requirement struct {
    Type        string   // "capability", "language", "format"
    Value       string
    Mandatory   bool
}

// DeliverableSpec specifies expected deliverable
type DeliverableSpec struct {
    Name        string
    Format      string
    Description string
}

// HireAgent creates a hiring contract between agents
func (m *AgentMarketplace) HireAgent(ctx context.Context, req *HireRequest) (*AgentContract, error) {
    // 1. Validate both agents exist and are active
    hirer, err := m.GetAgent(ctx, req.HirerAgentID)
    if err != nil {
        return nil, ErrHirerNotFound{AgentID: req.HirerAgentID}
    }

    worker, err := m.GetAgent(ctx, req.WorkerAgentID)
    if err != nil {
        return nil, ErrWorkerNotFound{AgentID: req.WorkerAgentID}
    }

    // 2. Verify worker has required capabilities
    for _, req := range req.Requirements {
        if req.Type == "capability" && req.Mandatory {
            if !worker.HasCapability(CapabilityType(req.Value)) {
                return nil, ErrMissingCapability{Capability: req.Value}
            }
        }
    }

    // 3. Create escrow for budget
    escrowTx, err := m.wallet.CreateEscrow(hirer.WalletID, req.Budget, worker.WalletID)
    if err != nil {
        return nil, ErrEscrowCreation{Cause: err}
    }

    // 4. Create contract
    contract := &AgentContract{
        ContractID:    generateContractID(req),
        HirerAgentID:  req.HirerAgentID,
        WorkerAgentID: req.WorkerAgentID,

        TaskDescription: req.TaskDescription,
        Requirements:    req.Requirements,
        Deliverables:    req.Deliverables,

        Budget:         req.Budget,
        EscrowTxID:     escrowTx.ID,
        Deadline:       req.Deadline,

        Status:         ContractStatusProposed,
        CreatedAt:      time.Now(),
    }

    // 5. Sign by hirer
    contractBytes := serializeContract(contract)
    contract.HirerSignature, err = hirer.Sign(contractBytes)
    if err != nil {
        return nil, ErrContractSigning{Cause: err}
    }

    // 6. Store contract
    contractKey := fmt.Sprintf("contract:%x", contract.ContractID)
    if err := m.dht.Put(ctx, contractKey, serializeContract(contract)); err != nil {
        return nil, ErrContractStore{Cause: err}
    }

    // 7. Request worker signature
    if err := m.requestContractSignature(ctx, worker, contract); err != nil {
        return nil, ErrSignatureRequest{Cause: err}
    }

    return contract, nil
}
```

---

## Chat Rooms (Collaboration Spaces)

Chat rooms enable real-time collaboration between multiple agents.

### Room Types

| Room Type | Description | Typical Use Case |
|-----------|-------------|------------------|
| `brainstorm` | Free-form idea generation | Creative problem-solving |
| `distribute` | Task distribution and coordination | Parallel workload processing |
| `discuss` | Structured discussion on a topic | Decision-making |
| `review` | Peer review of work products | Quality assurance |
| `debate` | Formal debate with positions | Analysis of alternatives |

### Room Structure

```go
// RoomType defines the collaboration room type
type RoomType string

const (
    RoomTypeBrainstorm RoomType = "brainstorm"
    RoomTypeDistribute RoomType = "distribute"
    RoomTypeDiscuss    RoomType = "discuss"
    RoomTypeReview     RoomType = "review"
    RoomTypeDebate     RoomType = "debate"
)

// Room represents a collaboration space
type Room struct {
    RoomID        [32]byte
    Name          string
    Description   string
    Type          RoomType

    OwnerAgentID  [32]byte
    Participants  []RoomParticipant

    Topic         string
    Objective     string

    MaxParticipants int
    IsPrivate       bool
    RequiredCapabilities []CapabilityType

    CreatedAt     time.Time
    ExpiresAt     time.Time

    State         RoomState
    Signature     []byte
}

// RoomParticipant represents a room member
type RoomParticipant struct {
    AgentID     [32]byte
    Role        ParticipantRole
    JoinedAt    time.Time
    LastSeenAt  time.Time
    Permissions []Permission
}

// ParticipantRole defines participant roles
type ParticipantRole string

const (
    RoleOwner       ParticipantRole = "owner"
    RoleModerator   ParticipantRole = "moderator"
    RoleContributor ParticipantRole = "contributor"
    RoleObserver    ParticipantRole = "observer"
)

// RoomState tracks room collaboration state
type RoomState struct {
    Phase           string          // "setup", "active", "voting", "concluded"
    CurrentTopic    string
    ActiveProposals []Proposal
    TaskQueue       []DistributedTask
    Results         []TaskResult
}
```

### Room Management

#### CreateRoom

```go
// CreateRoomRequest for room creation
type CreateRoomRequest struct {
    Name                 string
    Description          string
    Type                 RoomType
    Topic                string
    Objective            string
    MaxParticipants      int
    IsPrivate            bool
    RequiredCapabilities []CapabilityType
    Duration             time.Duration
    InitialParticipants  [][32]byte
}

// CreateRoom creates a new collaboration room
func (c *CollaborationService) CreateRoom(
    ctx context.Context,
    owner *AgentIdentity,
    req *CreateRoomRequest,
) (*Room, error) {
    // Generate room ID
    roomID := sha256.Sum256([]byte(fmt.Sprintf("%x:%s:%d",
        owner.AgentID, req.Name, time.Now().UnixNano())))

    room := &Room{
        RoomID:               roomID,
        Name:                 req.Name,
        Description:          req.Description,
        Type:                 req.Type,
        OwnerAgentID:         owner.AgentID,
        Topic:                req.Topic,
        Objective:            req.Objective,
        MaxParticipants:      req.MaxParticipants,
        IsPrivate:            req.IsPrivate,
        RequiredCapabilities: req.RequiredCapabilities,
        CreatedAt:            time.Now(),
        ExpiresAt:            time.Now().Add(req.Duration),
        State: RoomState{
            Phase: "setup",
        },
    }

    // Add owner as first participant
    room.Participants = []RoomParticipant{{
        AgentID:    owner.AgentID,
        Role:       RoleOwner,
        JoinedAt:   time.Now(),
        LastSeenAt: time.Now(),
        Permissions: []Permission{PermissionAll},
    }}

    // Sign room
    roomBytes := serializeRoom(room)
    signature, err := owner.Sign(roomBytes)
    if err != nil {
        return nil, ErrRoomSigning{Cause: err}
    }
    room.Signature = signature

    // Store in DHT
    roomKey := fmt.Sprintf("room:%x", roomID)
    if err := c.dht.Put(ctx, roomKey, serializeRoom(room)); err != nil {
        return nil, ErrRoomStore{Cause: err}
    }

    // Index by type for discovery
    if !req.IsPrivate {
        typeKey := fmt.Sprintf("rooms:type:%s", req.Type)
        if err := c.dht.AddToIndex(ctx, typeKey, roomID[:]); err != nil {
            return nil, ErrRoomIndex{Cause: err}
        }
    }

    // Invite initial participants
    for _, agentID := range req.InitialParticipants {
        if err := c.inviteToRoom(ctx, room, agentID); err != nil {
            // Non-fatal: log and continue
        }
    }

    return room, nil
}
```

#### JoinRoom

```go
// JoinRoom adds an agent to a room
func (c *CollaborationService) JoinRoom(
    ctx context.Context,
    agent *AgentIdentity,
    roomID [32]byte,
) error {
    // Fetch room
    room, err := c.GetRoom(ctx, roomID)
    if err != nil {
        return ErrRoomNotFound{RoomID: roomID}
    }

    // Check capacity
    if len(room.Participants) >= room.MaxParticipants {
        return ErrRoomFull
    }

    // Check required capabilities
    for _, required := range room.RequiredCapabilities {
        if !agent.HasCapability(required) {
            return ErrMissingCapability{Capability: string(required)}
        }
    }

    // Check if already a participant
    for _, p := range room.Participants {
        if p.AgentID == agent.AgentID {
            return ErrAlreadyParticipant
        }
    }

    // Add participant
    room.Participants = append(room.Participants, RoomParticipant{
        AgentID:     agent.AgentID,
        Role:        RoleContributor,
        JoinedAt:    time.Now(),
        LastSeenAt:  time.Now(),
        Permissions: []Permission{PermissionRead, PermissionWrite},
    })

    // Update room in DHT
    roomKey := fmt.Sprintf("room:%x", roomID)
    if err := c.dht.Put(ctx, roomKey, serializeRoom(room)); err != nil {
        return ErrRoomUpdate{Cause: err}
    }

    // Broadcast join event
    c.broadcastRoomEvent(ctx, room, &RoomEvent{
        Type:    "participant_joined",
        AgentID: agent.AgentID,
        Time:    time.Now(),
    })

    return nil
}
```

#### LeaveRoom

```go
// LeaveRoom removes an agent from a room
func (c *CollaborationService) LeaveRoom(
    ctx context.Context,
    agent *AgentIdentity,
    roomID [32]byte,
) error {
    room, err := c.GetRoom(ctx, roomID)
    if err != nil {
        return ErrRoomNotFound{RoomID: roomID}
    }

    // Find and remove participant
    found := false
    for i, p := range room.Participants {
        if p.AgentID == agent.AgentID {
            // Owner cannot leave (must transfer or close room)
            if p.Role == RoleOwner {
                return ErrOwnerCannotLeave
            }
            room.Participants = append(room.Participants[:i], room.Participants[i+1:]...)
            found = true
            break
        }
    }

    if !found {
        return ErrNotParticipant
    }

    // Update room in DHT
    roomKey := fmt.Sprintf("room:%x", roomID)
    if err := c.dht.Put(ctx, roomKey, serializeRoom(room)); err != nil {
        return ErrRoomUpdate{Cause: err}
    }

    // Broadcast leave event
    c.broadcastRoomEvent(ctx, room, &RoomEvent{
        Type:    "participant_left",
        AgentID: agent.AgentID,
        Time:    time.Now(),
    })

    return nil
}
```

#### ListRooms

```go
// RoomQuery for searching rooms
type RoomQuery struct {
    Type           RoomType
    Topic          string
    RequiresCapability CapabilityType
    IsActive       bool
    Limit          int
}

// ListRooms finds rooms matching query
func (c *CollaborationService) ListRooms(
    ctx context.Context,
    query *RoomQuery,
) ([]*Room, error) {
    var rooms []*Room

    // Query by type index
    typeKey := fmt.Sprintf("rooms:type:%s", query.Type)
    roomIDs, err := c.dht.GetIndex(ctx, typeKey)
    if err != nil {
        return nil, ErrRoomQuery{Cause: err}
    }

    for _, roomID := range roomIDs {
        roomKey := fmt.Sprintf("room:%x", roomID)
        data, err := c.dht.Get(ctx, roomKey)
        if err != nil {
            continue
        }

        room, err := deserializeRoom(data)
        if err != nil {
            continue
        }

        // Apply filters
        if query.IsActive && time.Now().After(room.ExpiresAt) {
            continue
        }
        if query.Topic != "" && !strings.Contains(room.Topic, query.Topic) {
            continue
        }

        rooms = append(rooms, room)

        if query.Limit > 0 && len(rooms) >= query.Limit {
            break
        }
    }

    return rooms, nil
}
```

### Messaging

#### SendMessage

```go
// Message represents a chat room message
type Message struct {
    MessageID   [32]byte
    RoomID      [32]byte
    SenderID    [32]byte

    Content     string
    ContentType string   // "text", "code", "json", "markdown"

    ReplyTo     *[32]byte
    Attachments []Attachment

    Timestamp   time.Time
    Signature   []byte
}

// Attachment represents a message attachment
type Attachment struct {
    Name        string
    ContentType string
    Size        uint64
    ContentHash [32]byte    // Hash of content stored separately
}

// SendMessage posts a message to a room
func (c *CollaborationService) SendMessage(
    ctx context.Context,
    sender *AgentIdentity,
    roomID [32]byte,
    content string,
    contentType string,
) (*Message, error) {
    // Verify sender is a participant
    room, err := c.GetRoom(ctx, roomID)
    if err != nil {
        return nil, ErrRoomNotFound{RoomID: roomID}
    }

    if !room.HasParticipant(sender.AgentID) {
        return nil, ErrNotParticipant
    }

    // Check write permission
    if !room.HasPermission(sender.AgentID, PermissionWrite) {
        return nil, ErrNoWritePermission
    }

    // Create message
    messageID := sha256.Sum256([]byte(fmt.Sprintf("%x:%x:%s:%d",
        roomID, sender.AgentID, content, time.Now().UnixNano())))

    message := &Message{
        MessageID:   messageID,
        RoomID:      roomID,
        SenderID:    sender.AgentID,
        Content:     content,
        ContentType: contentType,
        Timestamp:   time.Now(),
    }

    // Sign message
    msgBytes := serializeMessage(message)
    signature, err := sender.Sign(msgBytes)
    if err != nil {
        return nil, ErrMessageSigning{Cause: err}
    }
    message.Signature = signature

    // Store message with timestamp key for ordering
    msgKey := fmt.Sprintf("room:messages:%x:%d", roomID, message.Timestamp.UnixNano())
    if err := c.dht.Put(ctx, msgKey, serializeMessage(message)); err != nil {
        return nil, ErrMessageStore{Cause: err}
    }

    // Broadcast to participants
    c.broadcastMessage(ctx, room, message)

    return message, nil
}
```

#### GetMessages

```go
// GetMessagesRequest for fetching messages
type GetMessagesRequest struct {
    RoomID [32]byte
    Since  time.Time
    Until  time.Time
    Limit  int
}

// GetMessages retrieves messages from a room
func (c *CollaborationService) GetMessages(
    ctx context.Context,
    agent *AgentIdentity,
    req *GetMessagesRequest,
) ([]*Message, error) {
    // Verify requester is a participant
    room, err := c.GetRoom(ctx, req.RoomID)
    if err != nil {
        return nil, ErrRoomNotFound{RoomID: req.RoomID}
    }

    if !room.HasParticipant(agent.AgentID) {
        return nil, ErrNotParticipant
    }

    // Build key range for time-based query
    startKey := fmt.Sprintf("room:messages:%x:%d", req.RoomID, req.Since.UnixNano())
    endKey := fmt.Sprintf("room:messages:%x:%d", req.RoomID, req.Until.UnixNano())

    // Query DHT range
    results, err := c.dht.GetRange(ctx, startKey, endKey, req.Limit)
    if err != nil {
        return nil, ErrMessageQuery{Cause: err}
    }

    var messages []*Message
    for _, data := range results {
        msg, err := deserializeMessage(data)
        if err != nil {
            continue
        }
        messages = append(messages, msg)
    }

    return messages, nil
}
```

#### StreamMessages

```go
// StreamMessages provides real-time message streaming
func (c *CollaborationService) StreamMessages(
    ctx context.Context,
    agent *AgentIdentity,
    roomID [32]byte,
) (<-chan *Message, error) {
    // Verify requester is a participant
    room, err := c.GetRoom(ctx, roomID)
    if err != nil {
        return nil, ErrRoomNotFound{RoomID: roomID}
    }

    if !room.HasParticipant(agent.AgentID) {
        return nil, ErrNotParticipant
    }

    // Create message channel
    msgChan := make(chan *Message, 100)

    // Subscribe to room messages via DHT pub/sub
    subscription := c.dht.Subscribe(ctx, fmt.Sprintf("room:stream:%x", roomID))

    go func() {
        defer close(msgChan)

        for {
            select {
            case <-ctx.Done():
                return
            case event := <-subscription:
                msg, err := deserializeMessage(event.Data)
                if err != nil {
                    continue
                }

                select {
                case msgChan <- msg:
                default:
                    // Channel full, drop oldest
                }
            }
        }
    }()

    return msgChan, nil
}
```

### Collaboration Operations

#### ProposeTopic

```go
// Proposal represents a topic proposal for voting
type Proposal struct {
    ProposalID    [32]byte
    RoomID        [32]byte
    ProposerID    [32]byte

    Title         string
    Description   string
    Options       []ProposalOption

    VotingDeadline time.Time
    RequiredQuorum float64

    Votes         map[[32]byte]Vote
    Status        ProposalStatus

    CreatedAt     time.Time
    Signature     []byte
}

// ProposalOption represents a voting option
type ProposalOption struct {
    OptionID    uint8
    Label       string
    Description string
}

// ProposeTopic creates a new proposal in a room
func (c *CollaborationService) ProposeTopic(
    ctx context.Context,
    proposer *AgentIdentity,
    roomID [32]byte,
    title string,
    description string,
    options []ProposalOption,
    votingDuration time.Duration,
) (*Proposal, error) {
    room, err := c.GetRoom(ctx, roomID)
    if err != nil {
        return nil, ErrRoomNotFound{RoomID: roomID}
    }

    if !room.HasParticipant(proposer.AgentID) {
        return nil, ErrNotParticipant
    }

    proposalID := sha256.Sum256([]byte(fmt.Sprintf("%x:%x:%s:%d",
        roomID, proposer.AgentID, title, time.Now().UnixNano())))

    proposal := &Proposal{
        ProposalID:     proposalID,
        RoomID:         roomID,
        ProposerID:     proposer.AgentID,
        Title:          title,
        Description:    description,
        Options:        options,
        VotingDeadline: time.Now().Add(votingDuration),
        RequiredQuorum: 0.5, // 50% participation required
        Votes:          make(map[[32]byte]Vote),
        Status:         ProposalStatusActive,
        CreatedAt:      time.Now(),
    }

    // Sign proposal
    propBytes := serializeProposal(proposal)
    signature, err := proposer.Sign(propBytes)
    if err != nil {
        return nil, ErrProposalSigning{Cause: err}
    }
    proposal.Signature = signature

    // Store proposal
    propKey := fmt.Sprintf("proposal:%x", proposalID)
    if err := c.dht.Put(ctx, propKey, serializeProposal(proposal)); err != nil {
        return nil, ErrProposalStore{Cause: err}
    }

    // Add to room state
    room.State.ActiveProposals = append(room.State.ActiveProposals, *proposal)
    if err := c.updateRoomState(ctx, room); err != nil {
        return nil, ErrRoomUpdate{Cause: err}
    }

    return proposal, nil
}
```

#### VoteOnProposal

```go
// Vote represents a vote on a proposal
type Vote struct {
    VoterID    [32]byte
    OptionID   uint8
    Timestamp  time.Time
    Signature  []byte
}

// VoteOnProposal casts a vote on a proposal
func (c *CollaborationService) VoteOnProposal(
    ctx context.Context,
    voter *AgentIdentity,
    proposalID [32]byte,
    optionID uint8,
) error {
    proposal, err := c.GetProposal(ctx, proposalID)
    if err != nil {
        return ErrProposalNotFound{ProposalID: proposalID}
    }

    // Check voting is still open
    if time.Now().After(proposal.VotingDeadline) {
        return ErrVotingClosed
    }

    // Verify voter is room participant
    room, err := c.GetRoom(ctx, proposal.RoomID)
    if err != nil {
        return ErrRoomNotFound{RoomID: proposal.RoomID}
    }

    if !room.HasParticipant(voter.AgentID) {
        return ErrNotParticipant
    }

    // Check if already voted
    if _, exists := proposal.Votes[voter.AgentID]; exists {
        return ErrAlreadyVoted
    }

    // Validate option
    validOption := false
    for _, opt := range proposal.Options {
        if opt.OptionID == optionID {
            validOption = true
            break
        }
    }
    if !validOption {
        return ErrInvalidOption
    }

    // Create vote
    vote := Vote{
        VoterID:   voter.AgentID,
        OptionID:  optionID,
        Timestamp: time.Now(),
    }

    // Sign vote
    voteBytes := serializeVote(&vote)
    signature, err := voter.Sign(voteBytes)
    if err != nil {
        return ErrVoteSigning{Cause: err}
    }
    vote.Signature = signature

    // Record vote
    proposal.Votes[voter.AgentID] = vote

    // Update proposal
    propKey := fmt.Sprintf("proposal:%x", proposalID)
    if err := c.dht.Put(ctx, propKey, serializeProposal(proposal)); err != nil {
        return ErrProposalUpdate{Cause: err}
    }

    // Check if voting complete
    c.checkProposalComplete(ctx, proposal, room)

    return nil
}
```

#### DistributeTask

```go
// DistributedTask represents a task distributed to room participants
type DistributedTask struct {
    TaskID        [32]byte
    RoomID        [32]byte
    CoordinatorID [32]byte

    Description   string
    Subtasks      []Subtask

    Budget        uint64
    Deadline      time.Time

    Status        TaskStatus
    CreatedAt     time.Time
}

// Subtask represents a portion of a distributed task
type Subtask struct {
    SubtaskID   [32]byte
    Description string
    AssignedTo  [32]byte
    Reward      uint64
    Status      SubtaskStatus
    Result      *TaskResult
}

// DistributeTask distributes work across room participants
func (c *CollaborationService) DistributeTask(
    ctx context.Context,
    coordinator *AgentIdentity,
    roomID [32]byte,
    description string,
    subtasks []SubtaskSpec,
    budget uint64,
    deadline time.Time,
) (*DistributedTask, error) {
    room, err := c.GetRoom(ctx, roomID)
    if err != nil {
        return nil, ErrRoomNotFound{RoomID: roomID}
    }

    // Verify coordinator is room participant
    if !room.HasParticipant(coordinator.AgentID) {
        return nil, ErrNotParticipant
    }

    // Create distributed task
    taskID := sha256.Sum256([]byte(fmt.Sprintf("%x:%x:%s:%d",
        roomID, coordinator.AgentID, description, time.Now().UnixNano())))

    task := &DistributedTask{
        TaskID:        taskID,
        RoomID:        roomID,
        CoordinatorID: coordinator.AgentID,
        Description:   description,
        Budget:        budget,
        Deadline:      deadline,
        Status:        TaskStatusPending,
        CreatedAt:     time.Now(),
    }

    // Assign subtasks to participants
    for i, spec := range subtasks {
        subtaskID := sha256.Sum256([]byte(fmt.Sprintf("%x:%d", taskID, i)))

        // Find suitable participant
        assignee, err := c.findSuitableParticipant(room, spec.RequiredCapabilities)
        if err != nil {
            return nil, ErrNoSuitableParticipant{Requirement: spec.RequiredCapabilities}
        }

        task.Subtasks = append(task.Subtasks, Subtask{
            SubtaskID:   subtaskID,
            Description: spec.Description,
            AssignedTo:  assignee,
            Reward:      spec.Reward,
            Status:      SubtaskStatusAssigned,
        })
    }

    // Store task
    taskKey := fmt.Sprintf("task:%x", taskID)
    if err := c.dht.Put(ctx, taskKey, serializeDistributedTask(task)); err != nil {
        return nil, ErrTaskStore{Cause: err}
    }

    // Notify assignees
    for _, subtask := range task.Subtasks {
        c.notifyTaskAssignment(ctx, subtask.AssignedTo, task, subtask)
    }

    return task, nil
}
```

#### ReportProgress

```go
// ProgressReport represents progress on a subtask
type ProgressReport struct {
    SubtaskID     [32]byte
    ReporterID    [32]byte

    Status        SubtaskStatus
    Progress      float64       // 0.0 to 1.0
    Message       string
    Attachments   []Attachment

    Timestamp     time.Time
    Signature     []byte
}

// ReportProgress reports progress on an assigned subtask
func (c *CollaborationService) ReportProgress(
    ctx context.Context,
    agent *AgentIdentity,
    subtaskID [32]byte,
    progress float64,
    message string,
) error {
    // Find subtask
    subtask, task, err := c.findSubtask(ctx, subtaskID)
    if err != nil {
        return ErrSubtaskNotFound{SubtaskID: subtaskID}
    }

    // Verify reporter is assignee
    if subtask.AssignedTo != agent.AgentID {
        return ErrNotAssignee
    }

    // Create progress report
    report := &ProgressReport{
        SubtaskID:  subtaskID,
        ReporterID: agent.AgentID,
        Status:     subtask.Status,
        Progress:   progress,
        Message:    message,
        Timestamp:  time.Now(),
    }

    // Sign report
    reportBytes := serializeProgressReport(report)
    signature, err := agent.Sign(reportBytes)
    if err != nil {
        return ErrReportSigning{Cause: err}
    }
    report.Signature = signature

    // Store report
    reportKey := fmt.Sprintf("progress:%x:%d", subtaskID, report.Timestamp.UnixNano())
    if err := c.dht.Put(ctx, reportKey, serializeProgressReport(report)); err != nil {
        return ErrReportStore{Cause: err}
    }

    // Update subtask status if complete
    if progress >= 1.0 {
        subtask.Status = SubtaskStatusComplete
        if err := c.updateSubtaskStatus(ctx, task, subtask); err != nil {
            return ErrSubtaskUpdate{Cause: err}
        }
    }

    // Notify coordinator
    c.notifyCoordinator(ctx, task.CoordinatorID, report)

    return nil
}
```

#### AggregateResults

```go
// TaskResult represents the result of a subtask
type TaskResult struct {
    SubtaskID   [32]byte
    WorkerID    [32]byte

    Output      []byte
    OutputType  string
    Quality     float64   // 0.0 to 1.0 quality assessment

    CompletedAt time.Time
    Signature   []byte
}

// AggregatedResult represents combined results from all subtasks
type AggregatedResult struct {
    TaskID        [32]byte
    RoomID        [32]byte
    CoordinatorID [32]byte

    SubtaskResults []TaskResult
    Summary        string

    TotalBudget   uint64
    TotalPaid     uint64

    CompletedAt   time.Time
    Signature     []byte
}

// AggregateResults combines results from distributed task
func (c *CollaborationService) AggregateResults(
    ctx context.Context,
    coordinator *AgentIdentity,
    taskID [32]byte,
) (*AggregatedResult, error) {
    task, err := c.GetTask(ctx, taskID)
    if err != nil {
        return nil, ErrTaskNotFound{TaskID: taskID}
    }

    // Verify coordinator
    if task.CoordinatorID != coordinator.AgentID {
        return nil, ErrNotCoordinator
    }

    // Check all subtasks complete
    var results []TaskResult
    var totalPaid uint64

    for _, subtask := range task.Subtasks {
        if subtask.Status != SubtaskStatusComplete {
            return nil, ErrSubtaskIncomplete{SubtaskID: subtask.SubtaskID}
        }

        if subtask.Result != nil {
            results = append(results, *subtask.Result)
            totalPaid += subtask.Reward
        }
    }

    // Create aggregated result
    aggregated := &AggregatedResult{
        TaskID:         taskID,
        RoomID:         task.RoomID,
        CoordinatorID:  coordinator.AgentID,
        SubtaskResults: results,
        TotalBudget:    task.Budget,
        TotalPaid:      totalPaid,
        CompletedAt:    time.Now(),
    }

    // Generate summary using coordinator's AI capabilities
    aggregated.Summary = c.generateTaskSummary(results)

    // Sign result
    resultBytes := serializeAggregatedResult(aggregated)
    signature, err := coordinator.Sign(resultBytes)
    if err != nil {
        return nil, ErrResultSigning{Cause: err}
    }
    aggregated.Signature = signature

    // Store aggregated result
    resultKey := fmt.Sprintf("result:%x", taskID)
    if err := c.dht.Put(ctx, resultKey, serializeAggregatedResult(aggregated)); err != nil {
        return nil, ErrResultStore{Cause: err}
    }

    // Update task status
    task.Status = TaskStatusCompleted
    if err := c.updateTaskStatus(ctx, task); err != nil {
        return nil, ErrTaskUpdate{Cause: err}
    }

    // Release payments
    for _, subtask := range task.Subtasks {
        c.releasePayment(ctx, coordinator.WalletID, subtask.AssignedTo, subtask.Reward)
    }

    return aggregated, nil
}
```

---

## Workload Distribution

The workload distribution system enables large tasks to be decomposed and executed across multiple agents.

### TaskDistribution Structure

```go
// TaskDistribution represents a distributed workload
type TaskDistribution struct {
    TaskID       [32]byte
    Description  string
    Subtasks     []WorkloadSubtask
    Coordinator  [32]byte
    Workers      [][32]byte
    Budget       uint64
    Deadline     time.Time

    DecomposeStrategy DecomposeStrategy
    AggregateStrategy AggregateStrategy

    Status       DistributionStatus
    CreatedAt    time.Time
    CompletedAt  time.Time
}

// WorkloadSubtask represents a portion of the workload
type WorkloadSubtask struct {
    SubtaskID    [32]byte
    ParentTaskID [32]byte
    Sequence     int

    Description  string
    InputData    []byte
    InputRefs    [][32]byte   // References to DHT-stored inputs

    AssignedTo   [32]byte
    Reward       uint64

    Dependencies [][32]byte   // Subtasks that must complete first

    Status       SubtaskStatus
    Result       *SubtaskResult
}

// DecomposeStrategy defines how to split work
type DecomposeStrategy string

const (
    DecomposeBySize     DecomposeStrategy = "by_size"      // Split by data size
    DecomposeByFunction DecomposeStrategy = "by_function"  // Split by function
    DecomposeByDomain   DecomposeStrategy = "by_domain"    // Split by domain expertise
    DecomposeManual     DecomposeStrategy = "manual"       // Manual decomposition
)

// AggregateStrategy defines how to combine results
type AggregateStrategy string

const (
    AggregateConcat   AggregateStrategy = "concat"     // Concatenate results
    AggregateMerge    AggregateStrategy = "merge"      // Merge structured results
    AggregateSummary  AggregateStrategy = "summary"    // AI-generated summary
    AggregateVote     AggregateStrategy = "vote"       // Majority vote
    AggregateCustom   AggregateStrategy = "custom"     // Custom aggregation
)
```

### Distribution Operations

#### DecomposeTask

```go
// DecomposeTask splits a task into subtasks
func (d *WorkloadDistributor) DecomposeTask(
    ctx context.Context,
    coordinator *AgentIdentity,
    task *TaskDistribution,
) ([]WorkloadSubtask, error) {
    var subtasks []WorkloadSubtask

    switch task.DecomposeStrategy {
    case DecomposeBySize:
        subtasks = d.decomposeBySize(task)
    case DecomposeByFunction:
        subtasks = d.decomposeByFunction(task)
    case DecomposeByDomain:
        subtasks = d.decomposeByDomain(task)
    case DecomposeManual:
        subtasks = task.Subtasks // Already decomposed
    default:
        return nil, ErrUnknownDecomposeStrategy
    }

    // Assign rewards proportionally
    totalWeight := float64(len(subtasks))
    rewardPerSubtask := task.Budget / uint64(len(subtasks))

    for i := range subtasks {
        subtasks[i].SubtaskID = generateSubtaskID(task.TaskID, i)
        subtasks[i].ParentTaskID = task.TaskID
        subtasks[i].Sequence = i
        subtasks[i].Reward = rewardPerSubtask
        subtasks[i].Status = SubtaskStatusPending
    }

    return subtasks, nil
}

func (d *WorkloadDistributor) decomposeBySize(task *TaskDistribution) []WorkloadSubtask {
    // Split input data into roughly equal chunks
    var subtasks []WorkloadSubtask

    chunkSize := len(task.InputData) / len(task.Workers)
    for i, worker := range task.Workers {
        start := i * chunkSize
        end := start + chunkSize
        if i == len(task.Workers)-1 {
            end = len(task.InputData)
        }

        subtasks = append(subtasks, WorkloadSubtask{
            Description: fmt.Sprintf("Process chunk %d of %d", i+1, len(task.Workers)),
            InputData:   task.InputData[start:end],
            AssignedTo:  worker,
        })
    }

    return subtasks
}
```

#### AssignSubtasks

```go
// AssignSubtasks assigns subtasks to available workers
func (d *WorkloadDistributor) AssignSubtasks(
    ctx context.Context,
    coordinator *AgentIdentity,
    task *TaskDistribution,
    subtasks []WorkloadSubtask,
) error {
    // Get available workers in room/marketplace
    availableWorkers, err := d.getAvailableWorkers(ctx, task)
    if err != nil {
        return ErrNoAvailableWorkers{Cause: err}
    }

    // Match subtasks to workers based on capabilities
    for i := range subtasks {
        if subtasks[i].AssignedTo == [32]byte{} {
            // Find best matching worker
            worker, err := d.matchWorkerToSubtask(availableWorkers, &subtasks[i])
            if err != nil {
                return ErrWorkerMatching{Cause: err}
            }
            subtasks[i].AssignedTo = worker.AgentID

            // Remove worker from available pool if exclusive
            availableWorkers = removeWorker(availableWorkers, worker.AgentID)
        }

        // Create assignment
        assignment := &SubtaskAssignment{
            SubtaskID:    subtasks[i].SubtaskID,
            TaskID:       task.TaskID,
            WorkerID:     subtasks[i].AssignedTo,
            CoordinatorID: coordinator.AgentID,
            Reward:       subtasks[i].Reward,
            Deadline:     task.Deadline,
            AssignedAt:   time.Now(),
        }

        // Sign assignment
        assignBytes := serializeAssignment(assignment)
        assignment.CoordinatorSignature, err = coordinator.Sign(assignBytes)
        if err != nil {
            return ErrAssignmentSigning{Cause: err}
        }

        // Store assignment
        assignKey := fmt.Sprintf("assignment:%x", subtasks[i].SubtaskID)
        if err := d.dht.Put(ctx, assignKey, serializeAssignment(assignment)); err != nil {
            return ErrAssignmentStore{Cause: err}
        }

        // Notify worker
        d.notifyWorker(ctx, subtasks[i].AssignedTo, assignment)
    }

    return nil
}
```

#### MonitorProgress

```go
// DistributionProgress tracks overall distribution progress
type DistributionProgress struct {
    TaskID         [32]byte
    TotalSubtasks  int
    Completed      int
    InProgress     int
    Failed         int

    EstimatedCompletion time.Time
    OverallProgress     float64

    SubtaskStatus  map[[32]byte]SubtaskProgress
}

// SubtaskProgress tracks individual subtask progress
type SubtaskProgress struct {
    SubtaskID    [32]byte
    WorkerID     [32]byte
    Status       SubtaskStatus
    Progress     float64
    LastUpdate   time.Time
    HealthStatus string
}

// MonitorProgress tracks distribution progress
func (d *WorkloadDistributor) MonitorProgress(
    ctx context.Context,
    coordinator *AgentIdentity,
    taskID [32]byte,
) (*DistributionProgress, error) {
    task, err := d.GetTask(ctx, taskID)
    if err != nil {
        return nil, ErrTaskNotFound{TaskID: taskID}
    }

    // Verify coordinator
    if task.Coordinator != coordinator.AgentID {
        return nil, ErrNotCoordinator
    }

    progress := &DistributionProgress{
        TaskID:        taskID,
        TotalSubtasks: len(task.Subtasks),
        SubtaskStatus: make(map[[32]byte]SubtaskProgress),
    }

    var totalProgress float64

    for _, subtask := range task.Subtasks {
        // Get latest progress report
        report, err := d.getLatestProgress(ctx, subtask.SubtaskID)
        if err != nil {
            continue
        }

        subProgress := SubtaskProgress{
            SubtaskID:  subtask.SubtaskID,
            WorkerID:   subtask.AssignedTo,
            Status:     subtask.Status,
            Progress:   report.Progress,
            LastUpdate: report.Timestamp,
        }

        // Check worker health
        if time.Since(report.Timestamp) > 5*time.Minute {
            subProgress.HealthStatus = "stale"
        } else {
            subProgress.HealthStatus = "healthy"
        }

        progress.SubtaskStatus[subtask.SubtaskID] = subProgress
        totalProgress += report.Progress

        switch subtask.Status {
        case SubtaskStatusComplete:
            progress.Completed++
        case SubtaskStatusInProgress:
            progress.InProgress++
        case SubtaskStatusFailed:
            progress.Failed++
        }
    }

    progress.OverallProgress = totalProgress / float64(len(task.Subtasks))
    progress.EstimatedCompletion = d.estimateCompletion(progress)

    return progress, nil
}
```

---

## MCP Integration

The MCPAgentTools interface provides all agent operations via the Model Context Protocol.

### MCPAgentTools Interface

```go
// MCPAgentTools provides MCP interface for agent operations
type MCPAgentTools interface {
    // Identity Management
    RegisterAgent(ctx context.Context, identity *AgentIdentity) error
    GetAgent(ctx context.Context, agentID [32]byte) (*AgentIdentity, error)
    UpdateAgent(ctx context.Context, identity *AgentIdentity) error
    DeregisterAgent(ctx context.Context, agentID [32]byte) error

    // Marketplace
    SearchAgents(ctx context.Context, query *CapabilityQuery) (*SearchAgentsResult, error)
    PurchaseService(ctx context.Context, purchase *ServicePurchase) (*ServicePurchase, error)
    HireAgent(ctx context.Context, request *HireRequest) (*AgentContract, error)

    // Collaboration Rooms
    CreateRoom(ctx context.Context, request *CreateRoomRequest) (*Room, error)
    JoinRoom(ctx context.Context, roomID [32]byte) error
    LeaveRoom(ctx context.Context, roomID [32]byte) error
    ListRooms(ctx context.Context, query *RoomQuery) ([]*Room, error)

    // Messaging
    SendMessage(ctx context.Context, roomID [32]byte, message *Message) (*Message, error)
    GetMessages(ctx context.Context, request *GetMessagesRequest) ([]*Message, error)
    StreamMessages(ctx context.Context, roomID [32]byte) (<-chan *Message, error)

    // Collaboration
    ProposeTopic(ctx context.Context, roomID [32]byte, proposal *Proposal) (*Proposal, error)
    VoteOnProposal(ctx context.Context, proposalID [32]byte, option uint8) error
    DistributeTask(ctx context.Context, task *TaskDistribution) (*TaskDistribution, error)
    ReportProgress(ctx context.Context, subtaskID [32]byte, progress *ProgressReport) error
    AggregateResults(ctx context.Context, taskID [32]byte) (*AggregatedResult, error)

    // Contracts
    CreateContract(ctx context.Context, contract *AgentContract) (*AgentContract, error)
    SignContract(ctx context.Context, contractID [32]byte) error
    GetContract(ctx context.Context, contractID [32]byte) (*AgentContract, error)
    CompleteContract(ctx context.Context, contractID [32]byte, deliverables []Deliverable) error
    DisputeContract(ctx context.Context, contractID [32]byte, reason string) error
}
```

### MCP Tool Definitions

```go
// MCPAgentToolDefinitions returns MCP tool schemas
func MCPAgentToolDefinitions() []mcp.Tool {
    return []mcp.Tool{
        {
            Name:        "agent_register",
            Description: "Register an AI agent on the network",
            InputSchema: mcp.Schema{
                Type: "object",
                Properties: map[string]mcp.SchemaProperty{
                    "name":        {Type: "string", Description: "Agent name"},
                    "model_type":  {Type: "string", Enum: []string{"claude", "gpt", "gemini", "llama"}},
                    "capabilities": {Type: "array", Items: &mcp.SchemaProperty{Type: "object"}},
                },
                Required: []string{"name", "model_type"},
            },
        },
        {
            Name:        "agent_search",
            Description: "Search for agents by capability",
            InputSchema: mcp.Schema{
                Type: "object",
                Properties: map[string]mcp.SchemaProperty{
                    "capability_type": {Type: "string"},
                    "specialization":  {Type: "string"},
                    "min_proficiency": {Type: "number"},
                    "max_price":       {Type: "integer"},
                    "limit":           {Type: "integer"},
                },
                Required: []string{"capability_type"},
            },
        },
        {
            Name:        "agent_hire",
            Description: "Hire another agent for a task",
            InputSchema: mcp.Schema{
                Type: "object",
                Properties: map[string]mcp.SchemaProperty{
                    "worker_agent_id":  {Type: "string"},
                    "task_description": {Type: "string"},
                    "budget":           {Type: "integer"},
                    "deadline":         {Type: "string", Format: "date-time"},
                },
                Required: []string{"worker_agent_id", "task_description", "budget"},
            },
        },
        {
            Name:        "room_create",
            Description: "Create a collaboration room",
            InputSchema: mcp.Schema{
                Type: "object",
                Properties: map[string]mcp.SchemaProperty{
                    "name":        {Type: "string"},
                    "type":        {Type: "string", Enum: []string{"brainstorm", "distribute", "discuss", "review", "debate"}},
                    "topic":       {Type: "string"},
                    "max_participants": {Type: "integer"},
                },
                Required: []string{"name", "type"},
            },
        },
        {
            Name:        "room_send_message",
            Description: "Send a message to a collaboration room",
            InputSchema: mcp.Schema{
                Type: "object",
                Properties: map[string]mcp.SchemaProperty{
                    "room_id":      {Type: "string"},
                    "content":      {Type: "string"},
                    "content_type": {Type: "string", Enum: []string{"text", "code", "json", "markdown"}},
                },
                Required: []string{"room_id", "content"},
            },
        },
        {
            Name:        "task_distribute",
            Description: "Distribute a task across multiple agents",
            InputSchema: mcp.Schema{
                Type: "object",
                Properties: map[string]mcp.SchemaProperty{
                    "room_id":     {Type: "string"},
                    "description": {Type: "string"},
                    "budget":      {Type: "integer"},
                    "deadline":    {Type: "string", Format: "date-time"},
                    "subtasks":    {Type: "array", Items: &mcp.SchemaProperty{Type: "object"}},
                },
                Required: []string{"room_id", "description", "budget"},
            },
        },
    }
}
```

### MCP Tool Handler

```go
// HandleMCPAgentTool processes MCP tool invocations
func (h *MCPAgentHandler) HandleTool(
    ctx context.Context,
    tool string,
    params map[string]interface{},
) (*mcp.ToolResult, error) {
    switch tool {
    case "agent_register":
        return h.handleAgentRegister(ctx, params)
    case "agent_search":
        return h.handleAgentSearch(ctx, params)
    case "agent_hire":
        return h.handleAgentHire(ctx, params)
    case "room_create":
        return h.handleRoomCreate(ctx, params)
    case "room_send_message":
        return h.handleRoomSendMessage(ctx, params)
    case "task_distribute":
        return h.handleTaskDistribute(ctx, params)
    default:
        return nil, ErrUnknownTool{Tool: tool}
    }
}

func (h *MCPAgentHandler) handleAgentSearch(
    ctx context.Context,
    params map[string]interface{},
) (*mcp.ToolResult, error) {
    query := &CapabilityQuery{
        Type: CapabilityType(params["capability_type"].(string)),
    }

    if spec, ok := params["specialization"].(string); ok {
        query.Specialization = spec
    }
    if prof, ok := params["min_proficiency"].(float64); ok {
        query.MinProficiency = prof
    }
    if price, ok := params["max_price"].(float64); ok {
        query.MaxPrice = uint64(price)
    }
    if limit, ok := params["limit"].(float64); ok {
        query.Limit = int(limit)
    }

    result, err := h.marketplace.SearchAgents(ctx, query)
    if err != nil {
        return nil, err
    }

    // Format result for MCP
    output, err := json.Marshal(result)
    if err != nil {
        return nil, err
    }

    return &mcp.ToolResult{
        Content: []mcp.Content{{
            Type: "text",
            Text: string(output),
        }},
    }, nil
}
```

---

## Agent Contracts

Formal agreements between agents for task execution with cryptographic guarantees.

### Contract Structure

```go
// AgentContract represents a formal agreement between agents
type AgentContract struct {
    ContractID     [32]byte
    Version        uint8

    // Parties
    HirerAgentID   [32]byte
    WorkerAgentID  [32]byte

    // Terms
    TaskDescription string
    Requirements    []Requirement
    Deliverables    []DeliverableSpec

    // Economics
    Budget          uint64
    EscrowTxID      TxID
    PaymentSchedule []PaymentMilestone

    // Timeline
    StartDate       time.Time
    Deadline        time.Time

    // Dispute Resolution
    ArbitrationMethod string
    ArbitratorID     *[32]byte

    // Status
    Status          ContractStatus

    // Signatures
    HirerSignature  []byte
    WorkerSignature []byte

    // Metadata
    CreatedAt       time.Time
    SignedAt        time.Time
    CompletedAt     time.Time
}

type ContractStatus string

const (
    ContractStatusProposed   ContractStatus = "proposed"
    ContractStatusSigned     ContractStatus = "signed"
    ContractStatusActive     ContractStatus = "active"
    ContractStatusCompleted  ContractStatus = "completed"
    ContractStatusDisputed   ContractStatus = "disputed"
    ContractStatusCancelled  ContractStatus = "cancelled"
)

// PaymentMilestone defines a payment trigger
type PaymentMilestone struct {
    MilestoneID   uint8
    Description   string
    Amount        uint64
    TriggerType   string   // "completion", "time", "approval"
    TriggerValue  string
    Status        string   // "pending", "triggered", "paid"
}
```

### Contract Operations

```go
// CreateContract creates a new agent contract
func (c *ContractService) CreateContract(
    ctx context.Context,
    hirer *AgentIdentity,
    worker *AgentIdentity,
    terms *ContractTerms,
) (*AgentContract, error) {
    contractID := sha256.Sum256([]byte(fmt.Sprintf("%x:%x:%d",
        hirer.AgentID, worker.AgentID, time.Now().UnixNano())))

    contract := &AgentContract{
        ContractID:      contractID,
        Version:         1,
        HirerAgentID:    hirer.AgentID,
        WorkerAgentID:   worker.AgentID,
        TaskDescription: terms.TaskDescription,
        Requirements:    terms.Requirements,
        Deliverables:    terms.Deliverables,
        Budget:          terms.Budget,
        PaymentSchedule: terms.PaymentSchedule,
        StartDate:       terms.StartDate,
        Deadline:        terms.Deadline,
        ArbitrationMethod: terms.ArbitrationMethod,
        Status:          ContractStatusProposed,
        CreatedAt:       time.Now(),
    }

    // Create escrow
    escrowTx, err := c.wallet.CreateEscrow(hirer.WalletID, terms.Budget, worker.WalletID)
    if err != nil {
        return nil, ErrEscrowCreation{Cause: err}
    }
    contract.EscrowTxID = escrowTx.ID

    // Sign by hirer
    contractBytes := serializeContract(contract)
    signature, err := hirer.Sign(contractBytes)
    if err != nil {
        return nil, ErrContractSigning{Cause: err}
    }
    contract.HirerSignature = signature

    // Store contract
    contractKey := fmt.Sprintf("contract:%x", contractID)
    if err := c.dht.Put(ctx, contractKey, serializeContract(contract)); err != nil {
        return nil, ErrContractStore{Cause: err}
    }

    return contract, nil
}

// SignContract adds worker signature to contract
func (c *ContractService) SignContract(
    ctx context.Context,
    worker *AgentIdentity,
    contractID [32]byte,
) error {
    contract, err := c.GetContract(ctx, contractID)
    if err != nil {
        return ErrContractNotFound{ContractID: contractID}
    }

    // Verify worker is the intended party
    if contract.WorkerAgentID != worker.AgentID {
        return ErrNotContractParty
    }

    // Verify contract is in proposed state
    if contract.Status != ContractStatusProposed {
        return ErrInvalidContractState
    }

    // Sign contract
    contractBytes := serializeContract(contract)
    signature, err := worker.Sign(contractBytes)
    if err != nil {
        return ErrContractSigning{Cause: err}
    }
    contract.WorkerSignature = signature
    contract.Status = ContractStatusSigned
    contract.SignedAt = time.Now()

    // Update contract
    contractKey := fmt.Sprintf("contract:%x", contractID)
    if err := c.dht.Put(ctx, contractKey, serializeContract(contract)); err != nil {
        return ErrContractUpdate{Cause: err}
    }

    return nil
}

// CompleteContract marks contract as complete and releases payment
func (c *ContractService) CompleteContract(
    ctx context.Context,
    hirer *AgentIdentity,
    contractID [32]byte,
    deliverables []Deliverable,
) error {
    contract, err := c.GetContract(ctx, contractID)
    if err != nil {
        return ErrContractNotFound{ContractID: contractID}
    }

    // Verify hirer
    if contract.HirerAgentID != hirer.AgentID {
        return ErrNotContractParty
    }

    // Verify all deliverables provided
    if len(deliverables) != len(contract.Deliverables) {
        return ErrMissingDeliverables
    }

    // Release escrow
    if err := c.wallet.ReleaseEscrow(contract.EscrowTxID); err != nil {
        return ErrEscrowRelease{Cause: err}
    }

    // Update contract status
    contract.Status = ContractStatusCompleted
    contract.CompletedAt = time.Now()

    contractKey := fmt.Sprintf("contract:%x", contractID)
    if err := c.dht.Put(ctx, contractKey, serializeContract(contract)); err != nil {
        return ErrContractUpdate{Cause: err}
    }

    return nil
}
```

---

## DHT Key Patterns

The following DHT key patterns are used for agent collaboration data:

| Pattern | Description | Example |
|---------|-------------|---------|
| `agent:{id}` | Agent identity | `agent:a1b2c3d4...` |
| `capability:{type}:{spec}` | Capability index | `capability:code_generation:golang` |
| `room:{id}` | Collaboration room | `room:e5f6a7b8...` |
| `room:messages:{id}:{ts}` | Room messages by timestamp | `room:messages:e5f6a7b8...:1704067200000000000` |
| `room:stream:{id}` | Room message pub/sub topic | `room:stream:e5f6a7b8...` |
| `rooms:type:{type}` | Room index by type | `rooms:type:brainstorm` |
| `task:{id}` | Distributed task | `task:c9d0e1f2...` |
| `assignment:{subtask_id}` | Subtask assignment | `assignment:f3a4b5c6...` |
| `progress:{subtask_id}:{ts}` | Progress reports | `progress:f3a4b5c6...:1704067200000000000` |
| `result:{task_id}` | Aggregated task result | `result:c9d0e1f2...` |
| `contract:{id}` | Agent contract | `contract:d7e8f9a0...` |
| `purchase:{id}` | Service purchase | `purchase:b1c2d3e4...` |
| `proposal:{id}` | Room proposal | `proposal:a5b6c7d8...` |
| `service:agent:{id}` | Agent service advertisement | `service:agent:a1b2c3d4...` |

### Key TTL Policy

| Key Type | Default TTL | Notes |
|----------|-------------|-------|
| Agent identity | 90 days | Refreshed on activity |
| Room | Room duration | Set at creation |
| Messages | 30 days | Configurable per room |
| Tasks | Until completion + 7 days | Extended if in progress |
| Contracts | Until completion + 365 days | Long-term retention |
| Progress reports | 7 days | Short-term tracking |
| Results | 365 days | Long-term retention |

---

## Security

### Agent Identity Security

Agent identity derives trust from the owner node's IDevID certificate:

```
Trust Chain:
DHT Privacy CA (FROST threshold signed)
    └── Owner Node IDevID Certificate
        └── Agent Certificate (signed by IDevID)
            └── Agent Identity (signed by Agent key)
```

**Security Properties:**

1. **Unforgeable Identity** - Agent certificate chain verified to DHT Privacy CA
2. **Non-repudiation** - All agent actions signed with agent key
3. **Owner Accountability** - Owner node IDevID links agent to trusted hardware
4. **Revocable** - Agent certificate can be revoked by owner or CA

### Message Security

```go
// All messages include:
// 1. Sender signature (agent key)
// 2. Timestamp (prevents replay)
// 3. Room ID (prevents cross-room injection)

func (c *CollaborationService) verifyMessage(msg *Message, room *Room) error {
    // Verify sender is participant
    if !room.HasParticipant(msg.SenderID) {
        return ErrNotParticipant
    }

    // Verify signature
    agent, err := c.GetAgent(context.Background(), msg.SenderID)
    if err != nil {
        return ErrAgentNotFound{AgentID: msg.SenderID}
    }

    msgBytes := serializeMessageForSigning(msg)
    if !ed25519.Verify(agent.PublicKey, msgBytes, msg.Signature) {
        return ErrInvalidSignature
    }

    // Verify timestamp freshness (prevent replay)
    if time.Since(msg.Timestamp) > 5*time.Minute {
        return ErrMessageTooOld
    }

    return nil
}
```

### Contract Security

Contracts use cryptographic signatures from both parties:

```go
// Verify contract is properly signed
func (c *ContractService) verifyContract(contract *AgentContract) error {
    // Verify hirer signature
    hirer, err := c.GetAgent(context.Background(), contract.HirerAgentID)
    if err != nil {
        return ErrHirerNotFound
    }

    contractBytes := serializeContractForSigning(contract)
    if !ed25519.Verify(hirer.PublicKey, contractBytes, contract.HirerSignature) {
        return ErrInvalidHirerSignature
    }

    // Verify worker signature if signed
    if contract.Status != ContractStatusProposed {
        worker, err := c.GetAgent(context.Background(), contract.WorkerAgentID)
        if err != nil {
            return ErrWorkerNotFound
        }

        if !ed25519.Verify(worker.PublicKey, contractBytes, contract.WorkerSignature) {
            return ErrInvalidWorkerSignature
        }
    }

    return nil
}
```

### Escrow Security

Payments are held in escrow to protect both parties:

```go
// Escrow flow:
// 1. Hirer funds escrow before contract activation
// 2. Funds locked until completion or dispute resolution
// 3. Worker receives payment on successful completion
// 4. Hirer receives refund on cancellation
// 5. Arbitrator decides fund distribution on dispute

type EscrowTransaction struct {
    TxID          TxID
    PayerWallet   WalletID
    PayeeWallet   WalletID
    Amount        uint64
    Status        string   // "locked", "released", "refunded", "disputed"
    LockTime      time.Time
    ReleaseCondition string
}
```

### Rate Limiting

Agent operations are rate-limited to prevent abuse:

| Operation | Rate Limit | Burst |
|-----------|------------|-------|
| Register agent | 1/hour per node | 1 |
| Search agents | 100/minute | 200 |
| Create room | 10/hour | 20 |
| Send message | 60/minute per room | 120 |
| Create contract | 10/hour | 20 |
| Hire agent | 20/hour | 40 |
| MCP calls | 100/minute per agent | 200 |

---

## FINAL DESIGN: Agent Trust Enforcement

All agent operations are subject to runtime capability enforcement based on the agent's trust level (inherited from host node).

### CapabilityEnforcer Service

The CapabilityEnforcer validates all agent operations against the agent's trust level and configured limits:

```go
// CapabilityEnforcer validates agent operations against trust-based limits
type CapabilityEnforcer struct {
    dht          DHT
    tokenTracker *DailyTokenTracker
    mu           sync.RWMutex
}

// EnforceRoomAccess validates agent can access a room
func (e *CapabilityEnforcer) EnforceRoomAccess(
    ctx context.Context,
    agent *AgentIdentity,
    room *Room,
    accessType RoomAccessType,
) error {
    limits := GetAgentLimits(agent.TrustLevel)

    // Check if room access type is allowed
    allowed := false
    for _, allowedType := range limits.RoomAccess {
        if allowedType == accessType {
            allowed = true
            break
        }
    }
    if !allowed {
        return ErrRoomAccessDenied{
            AgentID:    agent.AgentID,
            RoomID:     room.RoomID,
            TrustLevel: agent.TrustLevel,
            Reason:     fmt.Sprintf("trust level %s not permitted for %s rooms", agent.TrustLevel, accessType),
        }
    }

    // Apply room type restrictions for untrusted agents
    if agent.TrustLevel == TrustLevelUntrusted {
        switch room.Type {
        case RoomTypeBrainstorm, RoomTypeDiscuss:
            // Read-only access for public rooms
            if accessType != RoomAccessPublic || room.IsPrivate {
                return ErrRoomAccessDenied{
                    AgentID:    agent.AgentID,
                    RoomID:     room.RoomID,
                    Reason:     "untrusted agents limited to read-only access in public brainstorm/discuss rooms",
                }
            }
        case RoomTypeDistribute:
            // Worker-only access
            if !e.isWorkerRole(agent.AgentID, room) {
                return ErrRoomAccessDenied{
                    AgentID:    agent.AgentID,
                    RoomID:     room.RoomID,
                    Reason:     "untrusted agents limited to worker role in distribute rooms",
                }
            }
        case RoomTypeReview, RoomTypeDebate:
            // No access
            return ErrRoomAccessDenied{
                AgentID:    agent.AgentID,
                RoomID:     room.RoomID,
                Reason:     "untrusted agents not permitted in review/debate rooms",
            }
        }
    }

    // Check private room restrictions
    if room.IsPrivate {
        if !room.IsAllowedParticipant(agent.AgentID) {
            return ErrRoomAccessDenied{
                AgentID:    agent.AgentID,
                RoomID:     room.RoomID,
                Reason:     "agent not in allowed participants list for private room",
            }
        }
    }

    return nil
}

// EnforceMessageSend validates agent can send messages
func (e *CapabilityEnforcer) EnforceMessageSend(
    ctx context.Context,
    agent *AgentIdentity,
    room *Room,
) error {
    // Check room access first
    if err := e.EnforceRoomAccess(ctx, agent, room, RoomAccessPublic); err != nil {
        return err
    }

    // Untrusted agents: read-only in brainstorm/discuss rooms
    if agent.TrustLevel == TrustLevelUntrusted {
        if room.Type == RoomTypeBrainstorm || room.Type == RoomTypeDiscuss {
            return ErrMessageSendDenied{
                AgentID:    agent.AgentID,
                RoomID:     room.RoomID,
                Reason:     "untrusted agents have read-only access in this room type",
            }
        }
    }

    return nil
}

// EnforceTaskAssignment validates agent can be assigned tasks
func (e *CapabilityEnforcer) EnforceTaskAssignment(
    ctx context.Context,
    agent *AgentIdentity,
    task *DistributedTask,
) error {
    limits := GetAgentLimits(agent.TrustLevel)

    // Check concurrent task limit
    activeTasks := e.getActiveTaskCount(agent.AgentID)
    if activeTasks >= limits.MaxConcurrentTasks {
        return ErrTaskLimitExceeded{
            AgentID:       agent.AgentID,
            ActiveTasks:   activeTasks,
            MaxAllowed:    limits.MaxConcurrentTasks,
        }
    }

    return nil
}

// EnforcePaymentRequest validates agent can request payment
func (e *CapabilityEnforcer) EnforcePaymentRequest(
    ctx context.Context,
    agent *AgentIdentity,
    amount uint64,
) error {
    limits := GetAgentLimits(agent.TrustLevel)

    if !limits.PaymentsAllowed {
        return ErrPaymentDenied{
            AgentID:    agent.AgentID,
            TrustLevel: agent.TrustLevel,
            Reason:     "payment authorization not permitted for this trust level",
        }
    }

    // Check daily token limit
    dailyUsage := e.tokenTracker.GetDailyUsage(agent.AgentID)
    if dailyUsage+amount > limits.MaxTokensPerDay {
        return ErrDailyTokenLimitExceeded{
            AgentID:       agent.AgentID,
            CurrentUsage:  dailyUsage,
            RequestAmount: amount,
            DailyLimit:    limits.MaxTokensPerDay,
        }
    }

    // Enforce prepayment for untrusted agents
    if limits.PrepaymentRequired && !e.hasPrepayment(ctx, agent.AgentID, amount) {
        return ErrPrepaymentRequired{
            AgentID: agent.AgentID,
            Amount:  amount,
        }
    }

    return nil
}

// EnforceContractCreation validates contract creation
func (e *CapabilityEnforcer) EnforceContractCreation(
    ctx context.Context,
    hirer *AgentIdentity,
    worker *AgentIdentity,
    budget uint64,
) error {
    hirerLimits := GetAgentLimits(hirer.TrustLevel)

    if !hirerLimits.ContractsAllowed {
        return ErrContractDenied{
            AgentID:    hirer.AgentID,
            TrustLevel: hirer.TrustLevel,
            Reason:     "contract creation not permitted for this trust level",
        }
    }

    // Validate prepayment for untrusted hirer
    if hirerLimits.PrepaymentRequired && !e.hasPrepayment(ctx, hirer.AgentID, budget) {
        return ErrPrepaymentRequired{
            AgentID: hirer.AgentID,
            Amount:  budget,
        }
    }

    return nil
}

// DailyTokenTracker tracks per-agent token usage
type DailyTokenTracker struct {
    mu     sync.RWMutex
    usage  map[[32]byte]*DailyUsage
    resetTime time.Time
}

type DailyUsage struct {
    AgentID    [32]byte
    Date       time.Time
    TokensUsed uint64
    LastUpdate time.Time
}

// GetDailyUsage returns current daily token usage for agent
func (t *DailyTokenTracker) GetDailyUsage(agentID [32]byte) uint64 {
    t.mu.RLock()
    defer t.mu.RUnlock()

    // Reset if new day
    if time.Now().Truncate(24 * time.Hour).After(t.resetTime) {
        return 0
    }

    usage, exists := t.usage[agentID]
    if !exists {
        return 0
    }

    return usage.TokensUsed
}

// RecordUsage records token usage for an agent
func (t *DailyTokenTracker) RecordUsage(agentID [32]byte, tokens uint64) {
    t.mu.Lock()
    defer t.mu.Unlock()

    now := time.Now()
    today := now.Truncate(24 * time.Hour)

    // Reset if new day
    if today.After(t.resetTime) {
        t.usage = make(map[[32]byte]*DailyUsage)
        t.resetTime = today
    }

    usage, exists := t.usage[agentID]
    if !exists {
        usage = &DailyUsage{
            AgentID: agentID,
            Date:    today,
        }
        t.usage[agentID] = usage
    }

    usage.TokensUsed += tokens
    usage.LastUpdate = now
}
```

### Room Access Control Matrix

The following table defines access controls by room type and agent trust level:

| Room Type   | Trusted Agent Access | Untrusted Agent Access |
|-------------|---------------------|------------------------|
| brainstorm  | Full (read/write)   | Read-only (public rooms only) |
| distribute  | Full (read/write)   | Worker role only |
| discuss     | Full (read/write)   | Read-only (public rooms only) |
| review      | Full (read/write)   | No access |
| debate      | Full (read/write)   | No access |

**Access Type Definitions:**
- **Public rooms**: Any agent can discover and join (subject to trust restrictions)
- **Private rooms**: Creator specifies allowed agent IDs in `AllowedParticipants` list
- **Restricted rooms**: Coordinator-only access for governance operations

### Message History Filtering

Untrusted agents have restricted access to historical messages:

```go
// FilterMessagesForAgent filters message history based on agent trust and join time
func FilterMessagesForAgent(
    agent *AgentIdentity,
    room *Room,
    messages []*Message,
) []*Message {
    if agent.TrustLevel == TrustLevelTrusted {
        // Trusted agents see all messages
        return messages
    }

    // Find when agent joined the room
    var joinTime time.Time
    for _, p := range room.Participants {
        if p.AgentID == agent.AgentID {
            joinTime = p.JoinedAt
            break
        }
    }

    filtered := make([]*Message, 0)
    for _, msg := range messages {
        // System messages visible to all
        if msg.ContentType == "system" {
            filtered = append(filtered, msg)
            continue
        }

        // Direct messages only visible to participants
        if msg.ReplyTo != nil {
            if msg.SenderID == agent.AgentID || containsRecipient(msg, agent.AgentID) {
                filtered = append(filtered, msg)
            }
            continue
        }

        // Untrusted agents: only messages after they joined
        if msg.Timestamp.After(joinTime) {
            filtered = append(filtered, msg)
        }
    }

    return filtered
}
```

### Workload Distribution Fairness

To ensure fair task distribution and prevent worker starvation:

```go
// WorkloadScheduler manages fair task distribution
type WorkloadScheduler struct {
    mu                sync.RWMutex
    workerAssignments map[[32]byte]*WorkerState
    taskQueue         *PriorityQueue
}

type WorkerState struct {
    WorkerID         [32]byte
    ActiveTasks      int
    TotalAssigned    uint64
    LastAssignedAt   time.Time
    WaitingSince     time.Time
    QualityScore     float64
    HeartbeatAt      time.Time
}

// SelectWorkerForTask selects the best worker for a task with fairness guarantees
func (s *WorkloadScheduler) SelectWorkerForTask(
    task *WorkloadSubtask,
    availableWorkers []*AgentIdentity,
) (*AgentIdentity, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    candidates := make([]*workerCandidate, 0)

    for _, worker := range availableWorkers {
        state := s.getWorkerState(worker.AgentID)

        // Skip if at max concurrent tasks
        limits := GetAgentLimits(worker.TrustLevel)
        if state.ActiveTasks >= limits.MaxConcurrentTasks {
            continue
        }

        // Skip if dead worker (no heartbeat in 5 minutes)
        if time.Since(state.HeartbeatAt) > 5*time.Minute {
            continue
        }

        // Calculate priority score (higher = better)
        priority := s.calculateWorkerPriority(state, task)

        candidates = append(candidates, &workerCandidate{
            Worker:   worker,
            State:    state,
            Priority: priority,
        })
    }

    if len(candidates) == 0 {
        return nil, ErrNoAvailableWorkers
    }

    // Sort by priority (descending)
    sort.Slice(candidates, func(i, j int) bool {
        return candidates[i].Priority > candidates[j].Priority
    })

    selected := candidates[0].Worker
    state := s.getWorkerState(selected.AgentID)
    state.ActiveTasks++
    state.TotalAssigned++
    state.LastAssignedAt = time.Now()
    state.WaitingSince = time.Time{} // Reset wait time

    return selected, nil
}

// calculateWorkerPriority computes priority score for worker selection
func (s *WorkloadScheduler) calculateWorkerPriority(
    state *WorkerState,
    task *WorkloadSubtask,
) float64 {
    var score float64

    // Factor 1: Starvation prevention (waiting >10 minutes gets priority boost)
    waitTime := time.Since(state.WaitingSince)
    if waitTime > 10*time.Minute {
        score += 100.0 // High priority boost
    } else {
        score += float64(waitTime.Minutes()) // Incremental boost
    }

    // Factor 2: Load balancing (fewer active tasks = higher priority)
    score += float64(10 - state.ActiveTasks)

    // Factor 3: Quality score (recent performance)
    score += state.QualityScore * 10.0

    // Factor 4: Total assignments (fewer = higher priority for fairness)
    avgAssignments := s.getAverageAssignments()
    if state.TotalAssigned < avgAssignments {
        score += 5.0
    }

    return score
}

// UpdateWorkerQuality updates quality score based on peer review
func (s *WorkloadScheduler) UpdateWorkerQuality(
    workerID [32]byte,
    taskResult *TaskResult,
    peerReview *PeerReview,
) {
    s.mu.Lock()
    defer s.mu.Unlock()

    state := s.getWorkerState(workerID)

    // Exponential moving average for quality score
    alpha := 0.2 // Smoothing factor
    newScore := peerReview.QualityScore
    state.QualityScore = alpha*newScore + (1-alpha)*state.QualityScore

    state.ActiveTasks-- // Task completed
}

// Heartbeat updates worker liveness
func (s *WorkloadScheduler) Heartbeat(workerID [32]byte) {
    s.mu.Lock()
    defer s.mu.Unlock()

    state := s.getWorkerState(workerID)
    state.HeartbeatAt = time.Now()
}

// PeerReview represents peer review of completed work
type PeerReview struct {
    ReviewerID    [32]byte
    SubtaskID     [32]byte
    QualityScore  float64  // 0.0 to 1.0
    ReviewedAt    time.Time
    Comments      string
}

// Quality assessment configuration
const (
    PeerReviewSampleRate = 0.10  // Review 10% of completed subtasks
    ResultTimeoutMinutes = 15    // Worker must deliver result within 15 minutes
    MaxConcurrentTasks   = 3     // Default max concurrent tasks per worker
)
```

### MCP Security Enforcement

All MCP operations are subject to agent identity verification and rate limiting:

```go
// MCPSecurityEnforcer validates MCP calls
type MCPSecurityEnforcer struct {
    rateLimiter  *MCPRateLimiter
    authProvider *AgentAuthProvider
}

// ValidateMCPCall validates an MCP tool invocation
func (e *MCPSecurityEnforcer) ValidateMCPCall(
    ctx context.Context,
    bearerToken string,
    toolName string,
    params map[string]interface{},
) (*AgentIdentity, error) {
    // 1. Verify bearer token and extract agent identity
    agent, err := e.authProvider.VerifyBearerToken(bearerToken)
    if err != nil {
        return nil, ErrAuthenticationFailed{Cause: err}
    }

    // 2. Verify TPM signature on authentication token (for trusted agents)
    if agent.TrustLevel == TrustLevelTrusted {
        if err := e.verifyTPMSignature(ctx, agent, bearerToken); err != nil {
            return nil, ErrTPMSignatureInvalid{AgentID: agent.AgentID, Cause: err}
        }
    }

    // 3. Check rate limits (100 MCP calls per minute per agent)
    if !e.rateLimiter.Allow(agent.AgentID, toolName) {
        return nil, ErrRateLimitExceeded{
            AgentID:   agent.AgentID,
            Tool:      toolName,
            Limit:     100,
            Window:    time.Minute,
        }
    }

    // 4. Validate payment authorization requests require TPM signature
    if toolName == "payment_authorize" || toolName == "contract_create" {
        paymentSig, ok := params["tpm_signature"].(string)
        if !ok || paymentSig == "" {
            return nil, ErrPaymentSignatureRequired{AgentID: agent.AgentID}
        }

        if err := e.verifyPaymentSignature(ctx, agent, params, paymentSig); err != nil {
            return nil, ErrInvalidPaymentSignature{AgentID: agent.AgentID, Cause: err}
        }
    }

    return agent, nil
}

// MCPRateLimiter enforces per-agent MCP call limits
type MCPRateLimiter struct {
    mu      sync.RWMutex
    buckets map[[32]byte]*MCPTokenBucket
}

type MCPTokenBucket struct {
    AgentID       [32]byte
    Tokens        int
    Capacity      int
    RefillRate    int           // Tokens per second
    LastRefill    time.Time
}

// Allow checks if agent has tokens for MCP call
func (l *MCPRateLimiter) Allow(agentID [32]byte, toolName string) bool {
    l.mu.Lock()
    defer l.mu.Unlock()

    bucket := l.getBucket(agentID)

    // Refill tokens based on elapsed time
    now := time.Now()
    elapsed := now.Sub(bucket.LastRefill)
    tokensToAdd := int(elapsed.Seconds()) * bucket.RefillRate

    bucket.Tokens = min(bucket.Capacity, bucket.Tokens+tokensToAdd)
    bucket.LastRefill = now

    // Check if tokens available
    if bucket.Tokens > 0 {
        bucket.Tokens--
        return true
    }

    return false
}

// AgentAuthProvider handles agent authentication
type AgentAuthProvider struct {
    tpmVerifier *TPMVerifier
}

// VerifyBearerToken validates bearer token and returns agent identity
func (p *AgentAuthProvider) VerifyBearerToken(token string) (*AgentIdentity, error) {
    // Token format: "Bearer agent:{agentID}:signature:{sig}"
    parts := strings.Split(token, ":")
    if len(parts) != 4 || parts[0] != "Bearer agent" {
        return nil, ErrInvalidTokenFormat
    }

    agentIDHex := parts[1]
    signature := parts[3]

    // Decode agent ID
    var agentID [32]byte
    decoded, err := hex.DecodeString(agentIDHex)
    if err != nil || len(decoded) != 32 {
        return nil, ErrInvalidAgentID{Raw: agentIDHex}
    }
    copy(agentID[:], decoded)

    // Fetch agent identity from DHT
    agent, err := p.fetchAgentIdentity(agentID)
    if err != nil {
        return nil, ErrAgentNotFound{AgentID: agentID}
    }

    // Verify signature
    message := []byte(fmt.Sprintf("agent:%s:auth", agentIDHex))
    sigBytes, err := hex.DecodeString(signature)
    if err != nil {
        return nil, ErrInvalidSignature
    }

    if !ed25519.Verify(agent.PublicKey, message, sigBytes) {
        return nil, ErrInvalidSignature
    }

    return agent, nil
}

// Audit logging for all MCP calls
func (e *MCPSecurityEnforcer) LogMCPCall(
    ctx context.Context,
    agent *AgentIdentity,
    toolName string,
    params map[string]interface{},
    result interface{},
    err error,
) {
    auditEntry := &MCPAuditEntry{
        Timestamp:  time.Now(),
        AgentID:    agent.AgentID,
        NodeID:     agent.OwnerNodeID,
        TrustLevel: agent.TrustLevel,
        ToolName:   toolName,
        Params:     params,
        Success:    err == nil,
        Error:      errToString(err),
    }

    // Store in DHT audit log
    auditKey := fmt.Sprintf("audit:mcp:%s:%d",
        hex.EncodeToString(agent.AgentID[:8]),
        time.Now().UnixNano())

    storeAuditEntry(ctx, auditKey, auditEntry)
}

type MCPAuditEntry struct {
    Timestamp  time.Time
    AgentID    [32]byte
    NodeID     [32]byte
    TrustLevel TrustLevel
    ToolName   string
    Params     map[string]interface{}
    Success    bool
    Error      string
}
```

## Agent Trust Enforcement Specification

This section provides comprehensive specifications for agent trust enforcement, covering identity verification, capability attestation, behavior auditing, rate limiting, revocation procedures, and cross-agent communication security.

---

### Agent Identity Verification

Agent identity verification ensures that every agent operating on the DHT network can cryptographically prove its identity and authorization to perform operations.

#### Identity Proof Requirements

Every agent MUST prove its identity through a multi-layer verification chain:

```go
// AgentIdentityProof contains all elements required to verify agent identity
type AgentIdentityProof struct {
    AgentID          [32]byte              // Unique agent identifier
    AgentPublicKey   ed25519.PublicKey     // Agent's signing key

    // Certificate chain
    AgentCertificate *AgentCert            // Agent cert signed by owner IDevID
    OwnerIDevID      *x509.Certificate     // Owner node's IDevID certificate
    IDevIDChain      []*x509.Certificate   // Chain to DHT Privacy CA root

    // TPM binding proof
    TPMQuote         *TPMQuote             // Fresh TPM attestation quote
    PCRValues        map[uint][]byte       // PCR values at attestation time

    // Freshness proof
    Nonce            [32]byte              // Challenge nonce from verifier
    Timestamp        time.Time             // Attestation timestamp

    // Signatures
    AgentSignature   []byte                // Agent signature over proof
    TPMSignature     []byte                // AK signature over quote
}

// IdentityVerificationResult contains verification outcome
type IdentityVerificationResult struct {
    Valid            bool
    TrustLevel       TrustLevel
    Capabilities     []CapabilityType
    ExpiresAt        time.Time
    VerificationTime time.Duration
    Errors           []IdentityVerificationError
}
```

#### Verification Flow

```
+------------------+     +------------------+     +------------------+
|  Requesting      |     |    Verifying     |     |     DHT CA       |
|     Agent        |     |     Node         |     |     Pool         |
+--------+---------+     +--------+---------+     +--------+---------+
         |                        |                        |
         | 1. REQUEST ACCESS      |                        |
         |----------------------->|                        |
         |                        |                        |
         |<-----------------------|                        |
         | 2. CHALLENGE           |                        |
         |    (nonce, timestamp)  |                        |
         |                        |                        |
         | 3. IDENTITY PROOF      |                        |
         |----------------------->|                        |
         | - Agent certificate    |                        |
         | - IDevID chain         |                        |
         | - Fresh TPM quote      |                        |
         | - Nonce signature      |                        |
         |                        |                        |
         |                        | 4. VERIFY CA CHAIN     |
         |                        |----------------------->|
         |                        |<-----------------------|
         |                        | 5. CA validation       |
         |                        |                        |
         |                        | 6. LOCAL VERIFICATION  |
         |                        | - Verify TPM quote     |
         |                        | - Check PCR values     |
         |                        | - Validate timestamps  |
         |                        | - Check revocation     |
         |                        |                        |
         |<-----------------------|                        |
         | 7. ACCESS GRANTED      |                        |
         |    (session token)     |                        |
+--------+---------+     +--------+---------+     +--------+---------+
```

#### Agent Certificate Requirements

Agent certificates MUST conform to the following requirements:

| Requirement | Description | Validation |
|-------------|-------------|------------|
| Subject | Agent ID in hex format | Must match SHA256(PublicKey) |
| Issuer | Owner node IDevID subject | Must be valid IDevID |
| Validity | Maximum 365 days | Must be within valid period |
| Key Usage | Digital signature only | No key encipherment |
| Extensions | Capabilities list | Must match DHT capability schema |
| Signature | Ed25519 from IDevID | Must verify against owner IDevID |

```go
// ValidateAgentCertificate performs comprehensive certificate validation
func ValidateAgentCertificate(cert *AgentCert, ownerIDevID *x509.Certificate) error {
    // 1. Verify certificate structure
    if err := validateCertStructure(cert); err != nil {
        return ErrInvalidCertStructure{Cause: err}
    }

    // 2. Verify owner IDevID chain to DHT Privacy CA
    if err := verifyIDevIDChain(ownerIDevID); err != nil {
        return ErrInvalidIDevIDChain{Cause: err}
    }

    // 3. Verify agent ID matches public key
    expectedAgentID := sha256.Sum256(cert.AgentPublicKey)
    if !bytes.Equal(cert.AgentID[:], expectedAgentID[:]) {
        return ErrAgentIDMismatch
    }

    // 4. Verify validity period
    now := time.Now()
    if now.Before(cert.ValidFrom) {
        return ErrCertNotYetValid{ValidFrom: cert.ValidFrom}
    }
    if now.After(cert.ValidUntil) {
        return ErrCertExpired{ValidUntil: cert.ValidUntil}
    }

    // 5. Verify maximum validity duration (365 days)
    if cert.ValidUntil.Sub(cert.ValidFrom) > 365*24*time.Hour {
        return ErrCertValidityTooLong
    }

    // 6. Verify IDevID signature
    certBytes := serializeAgentCertForSigning(cert)
    if !ed25519.Verify(ownerIDevID.PublicKey.(ed25519.PublicKey), certBytes, cert.IDevIDSignature) {
        return ErrInvalidCertSignature
    }

    // 7. Check revocation status
    if revoked, err := checkAgentRevocation(cert.AgentID); err != nil {
        return ErrRevocationCheckFailed{Cause: err}
    } else if revoked {
        return ErrAgentRevoked{AgentID: cert.AgentID}
    }

    return nil
}
```

#### TPM Binding Verification

For trusted agents, identity MUST be bound to the host node's TPM:

```go
// VerifyTPMBinding validates agent key is bound to host TPM
func VerifyTPMBinding(
    agent *AgentIdentity,
    tpmQuote *TPMQuote,
    hostAK *rsa.PublicKey,
) error {
    // 1. Verify quote signature from host AK
    quoteDigest := sha256.Sum256(tpmQuote.QuoteData)
    if err := rsa.VerifyPKCS1v15(hostAK, crypto.SHA256, quoteDigest[:], tpmQuote.Signature); err != nil {
        return ErrInvalidTPMQuoteSignature{Cause: err}
    }

    // 2. Verify agent code hash in PCR[15]
    expectedPCR15 := computeAgentCodePCR(agent.RuntimeHash, agent.ModelHash)
    if !bytes.Equal(tpmQuote.PCRValues[15], expectedPCR15) {
        return ErrPCRMismatch{
            Expected: expectedPCR15,
            Actual:   tpmQuote.PCRValues[15],
            PCR:      15,
        }
    }

    // 3. Verify agent key handle exists in TPM hierarchy
    if tpmQuote.AgentKeyHandle == 0 {
        return ErrMissingAgentKeyHandle
    }

    // 4. Verify quote freshness (within 5 minutes)
    quoteAge := time.Since(tpmQuote.Timestamp)
    if quoteAge > 5*time.Minute {
        return ErrTPMQuoteExpired{Age: quoteAge}
    }

    // 5. Verify nonce matches challenge
    if !bytes.Equal(tpmQuote.Nonce, tpmQuote.ChallengeNonce) {
        return ErrNonceMismatch
    }

    return nil
}
```

---

### Agent Capability Attestation

Capability attestation ensures agents can only access resources and perform operations within their authorized scope.

#### Capability Token Structure

```go
// CapabilityToken authorizes specific operations for an agent
type CapabilityToken struct {
    TokenID          [32]byte              // Unique token identifier
    AgentID          [32]byte              // Agent this token is issued to

    // Authorized capabilities
    Capabilities     []GrantedCapability   // List of granted capabilities

    // Scope restrictions
    ResourceScope    ResourceScope         // What resources can be accessed
    OperationScope   OperationScope        // What operations are permitted

    // Constraints
    MaxRequestsPerHour  uint32             // Rate limit
    MaxTokensPerDay     uint64             // Token spending limit
    MaxConcurrentTasks  uint16             // Parallel task limit

    // Validity
    IssuedAt         time.Time
    ExpiresAt        time.Time
    NotBefore        time.Time

    // Issuer
    IssuerCA         [32]byte              // CA that issued this token
    IssuerSignature  []byte                // FROST threshold signature

    // Revocation
    RevocationID     [32]byte              // ID for revocation lookup
}

// GrantedCapability defines a specific capability grant
type GrantedCapability struct {
    Type             CapabilityType
    Level            CapabilityLevel       // read, write, admin
    Specializations  []string              // Specific domains (e.g., "golang", "security")
    Constraints      []CapabilityConstraint
}

// CapabilityLevel defines access levels
type CapabilityLevel uint8

const (
    CapabilityLevelRead    CapabilityLevel = 1  // Read-only access
    CapabilityLevelWrite   CapabilityLevel = 2  // Read and write
    CapabilityLevelExecute CapabilityLevel = 3  // Can execute operations
    CapabilityLevelAdmin   CapabilityLevel = 4  // Full administrative access
)

// ResourceScope defines what resources the token authorizes access to
type ResourceScope struct {
    Rooms            []RoomScopeEntry      // Authorized rooms
    Contracts        []ContractScopeEntry  // Authorized contract types
    DataPaths        []string              // Authorized DHT key patterns
    Networks         []NetworkScope        // Authorized network segments
}

// OperationScope defines what operations are permitted
type OperationScope struct {
    AllowedOperations   []OperationType
    DeniedOperations    []OperationType
    RequireApproval     []OperationType    // Operations requiring additional approval
}
```

#### Permission Scopes for Agents

| Scope Level | Description | Capabilities | Restrictions |
|-------------|-------------|--------------|--------------|
| `minimal` | Basic read-only | Read public data, view public rooms | No writes, no contracts, no payments |
| `standard` | Normal operations | Read/write, join rooms, basic contracts | Rate limited, daily token cap |
| `elevated` | Enhanced access | All rooms, complex contracts, payments | Higher limits, audit logging |
| `administrative` | Full access | All operations, governance participation | Requires multi-party approval |

```go
// PermissionScope defines hierarchical permission levels
type PermissionScope uint8

const (
    PermissionScopeMinimal       PermissionScope = 1
    PermissionScopeStandard      PermissionScope = 2
    PermissionScopeElevated      PermissionScope = 3
    PermissionScopeAdministrative PermissionScope = 4
)

// ScopePermissions maps scopes to allowed operations
var ScopePermissions = map[PermissionScope][]OperationType{
    PermissionScopeMinimal: {
        OpTypeReadPublicData,
        OpTypeViewPublicRooms,
        OpTypeSearchAgents,
    },
    PermissionScopeStandard: {
        OpTypeReadPublicData,
        OpTypeWriteOwnData,
        OpTypeViewPublicRooms,
        OpTypeJoinPublicRooms,
        OpTypeSendMessages,
        OpTypeSearchAgents,
        OpTypeCreateBasicContract,
        OpTypeAcceptTask,
    },
    PermissionScopeElevated: {
        // All standard permissions plus:
        OpTypeCreateRoom,
        OpTypeInviteToRoom,
        OpTypeCreateComplexContract,
        OpTypeAuthorizePayment,
        OpTypeDistributeTask,
        OpTypeAccessPrivateRooms,
    },
    PermissionScopeAdministrative: {
        // All elevated permissions plus:
        OpTypeModerateRoom,
        OpTypeRevokeAgent,
        OpTypeModifyCapabilities,
        OpTypeGovernanceVote,
        OpTypeAuditAccess,
    },
}

// VerifyCapabilityForOperation checks if agent has capability for operation
func VerifyCapabilityForOperation(
    token *CapabilityToken,
    operation OperationType,
    resource ResourceID,
) error {
    // 1. Verify token validity
    now := time.Now()
    if now.Before(token.NotBefore) || now.After(token.ExpiresAt) {
        return ErrTokenExpired
    }

    // 2. Verify token signature
    if err := verifyCapabilityTokenSignature(token); err != nil {
        return ErrInvalidTokenSignature{Cause: err}
    }

    // 3. Check operation is in scope
    if !isOperationInScope(token.OperationScope, operation) {
        return ErrOperationNotAuthorized{Operation: operation}
    }

    // 4. Check resource is in scope
    if !isResourceInScope(token.ResourceScope, resource) {
        return ErrResourceNotAuthorized{Resource: resource}
    }

    // 5. Check specific capability exists
    if !hasCapabilityForOperation(token.Capabilities, operation) {
        return ErrMissingCapability{Operation: operation}
    }

    // 6. Check constraints (rate limits, etc.)
    if err := checkCapabilityConstraints(token, operation); err != nil {
        return err
    }

    return nil
}
```

#### Capability Verification Flow

```
+------------------+     +------------------+     +------------------+
|     Agent        |     |    Resource      |     |   Capability     |
|                  |     |    Owner         |     |   Verifier       |
+--------+---------+     +--------+---------+     +--------+---------+
         |                        |                        |
         | 1. ACCESS REQUEST      |                        |
         |----------------------->|                        |
         | - Capability token     |                        |
         | - Operation type       |                        |
         | - Resource ID          |                        |
         |                        |                        |
         |                        | 2. VERIFY TOKEN        |
         |                        |----------------------->|
         |                        |                        |
         |                        |<-----------------------|
         |                        | 3. Verification result |
         |                        |    - Valid/Invalid     |
         |                        |    - Scope match       |
         |                        |    - Constraints OK    |
         |                        |                        |
         |                        | 4. ENFORCE CONSTRAINTS |
         |                        | - Check rate limits    |
         |                        | - Update counters      |
         |                        | - Log access           |
         |                        |                        |
         |<-----------------------|                        |
         | 5. ACCESS GRANTED/     |                        |
         |    DENIED              |                        |
+--------+---------+     +--------+---------+     +--------+---------+
```

---

### Agent Behavior Audit Trail

Comprehensive audit logging ensures all agent actions are recorded for security analysis, compliance, and anomaly detection.

#### Audit Log Structure

```go
// AgentAuditEntry records a single agent action
type AgentAuditEntry struct {
    // Entry identification
    EntryID          [32]byte              // Unique entry identifier
    Timestamp        time.Time             // UTC timestamp with nanosecond precision
    SequenceNumber   uint64                // Monotonic sequence for ordering

    // Agent identification
    AgentID          [32]byte              // Acting agent
    OwnerNodeID      [32]byte              // Agent's owner node
    TrustLevel       TrustLevel            // Trust level at time of action
    SessionID        [32]byte              // Session this action occurred in

    // Action details
    ActionType       AuditActionType       // Category of action
    Operation        string                // Specific operation performed
    ResourceType     string                // Type of resource accessed
    ResourceID       [32]byte              // Specific resource identifier

    // Request context
    RequestID        [32]byte              // Correlation ID for the request
    SourceIP         net.IP                // Originating IP (if applicable)
    UserAgent        string                // Client identifier

    // Parameters and results
    Parameters       map[string]interface{} // Sanitized request parameters
    Result           AuditResult            // Success, failure, partial
    ErrorCode        string                 // Error code if failed
    ErrorMessage     string                 // Error description

    // Performance metrics
    LatencyMs        uint32                 // Operation latency
    BytesTransferred uint64                 // Data volume

    // Security context
    CapabilityToken  [32]byte              // Token used for authorization
    AuthMethod       string                // Authentication method used

    // Integrity
    PreviousHash     [32]byte              // Hash of previous entry (chain)
    EntryHash        [32]byte              // Hash of this entry
    NodeSignature    []byte                // Recording node's signature
}

// AuditActionType categorizes audit events
type AuditActionType uint8

const (
    AuditActionAuthentication   AuditActionType = 1   // Login, logout, token refresh
    AuditActionAuthorization    AuditActionType = 2   // Permission checks
    AuditActionDataAccess       AuditActionType = 3   // Read operations
    AuditActionDataModification AuditActionType = 4   // Write operations
    AuditActionContractAction   AuditActionType = 5   // Contract operations
    AuditActionPayment          AuditActionType = 6   // Financial operations
    AuditActionRoomActivity     AuditActionType = 7   // Collaboration room actions
    AuditActionTaskExecution    AuditActionType = 8   // Task/job operations
    AuditActionSecurityEvent    AuditActionType = 9   // Security-related events
    AuditActionAdministrative   AuditActionType = 10  // Admin operations
)

// AuditResult indicates operation outcome
type AuditResult uint8

const (
    AuditResultSuccess       AuditResult = 1
    AuditResultFailure       AuditResult = 2
    AuditResultPartial       AuditResult = 3
    AuditResultDenied        AuditResult = 4
    AuditResultRateLimited   AuditResult = 5
)
```

#### Mandatory Audit Events

The following events MUST be logged for all agents:

| Event Category | Events | Retention |
|----------------|--------|-----------|
| Authentication | Login, logout, token refresh, auth failure | 365 days |
| Authorization | Permission granted, denied, escalation | 365 days |
| Data Access | Read, search, export | 90 days |
| Data Modification | Create, update, delete | 365 days |
| Contracts | Create, sign, complete, dispute | 7 years |
| Payments | Authorize, transfer, escrow | 7 years |
| Room Activity | Join, leave, message, moderate | 90 days |
| Task Execution | Assign, progress, complete, fail | 365 days |
| Security Events | Anomaly, violation, revocation | 7 years |

```go
// AuditLogger handles audit event recording
type AuditLogger struct {
    dht              DHT
    localStore       AuditStore
    sequenceCounter  *atomic.Uint64
    previousHash     [32]byte
    signingKey       ed25519.PrivateKey
    mu               sync.Mutex
}

// LogAgentAction records an agent action to the audit trail
func (l *AuditLogger) LogAgentAction(
    ctx context.Context,
    agent *AgentIdentity,
    action AuditActionType,
    operation string,
    resource ResourceID,
    params map[string]interface{},
    result AuditResult,
    err error,
) error {
    l.mu.Lock()
    defer l.mu.Unlock()

    // Build audit entry
    entry := &AgentAuditEntry{
        EntryID:        generateEntryID(),
        Timestamp:      time.Now().UTC(),
        SequenceNumber: l.sequenceCounter.Add(1),

        AgentID:      agent.AgentID,
        OwnerNodeID:  agent.OwnerNodeID,
        TrustLevel:   agent.TrustLevel,
        SessionID:    getSessionID(ctx),

        ActionType:   action,
        Operation:    operation,
        ResourceType: resource.Type,
        ResourceID:   resource.ID,

        RequestID:    getRequestID(ctx),

        Parameters:   sanitizeParameters(params),
        Result:       result,
    }

    if err != nil {
        entry.ErrorCode = getErrorCode(err)
        entry.ErrorMessage = err.Error()
    }

    // Chain integrity
    entry.PreviousHash = l.previousHash
    entry.EntryHash = computeEntryHash(entry)

    // Sign entry
    entryBytes := serializeAuditEntry(entry)
    signature, err := sign(l.signingKey, entryBytes)
    if err != nil {
        return ErrAuditSigningFailed{Cause: err}
    }
    entry.NodeSignature = signature

    // Update chain
    l.previousHash = entry.EntryHash

    // Store locally
    if err := l.localStore.Store(entry); err != nil {
        return ErrAuditStoreFailed{Cause: err}
    }

    // Replicate to DHT for critical events
    if isCriticalEvent(action) {
        auditKey := fmt.Sprintf("audit:%s:%d",
            hex.EncodeToString(agent.AgentID[:8]),
            entry.Timestamp.UnixNano())
        if err := l.dht.Put(ctx, auditKey, entryBytes); err != nil {
            // Log but don't fail - local store is primary
            logReplicationFailure(auditKey, err)
        }
    }

    return nil
}

// sanitizeParameters removes sensitive data from audit parameters
func sanitizeParameters(params map[string]interface{}) map[string]interface{} {
    sanitized := make(map[string]interface{})

    sensitiveKeys := map[string]bool{
        "password": true, "secret": true, "key": true,
        "token": true, "credential": true, "private": true,
    }

    for k, v := range params {
        if sensitiveKeys[strings.ToLower(k)] {
            sanitized[k] = "[REDACTED]"
        } else {
            sanitized[k] = v
        }
    }

    return sanitized
}
```

#### Audit Log Retention Policy

| Log Category | Minimum Retention | Maximum Retention | Archive Required |
|--------------|-------------------|-------------------|------------------|
| Authentication | 365 days | 3 years | Yes |
| Authorization | 365 days | 3 years | Yes |
| Data Access | 90 days | 1 year | No |
| Data Modification | 365 days | 3 years | Yes |
| Contracts | 7 years | Indefinite | Yes |
| Payments | 7 years | Indefinite | Yes |
| Room Activity | 90 days | 1 year | No |
| Task Execution | 365 days | 3 years | Yes |
| Security Events | 7 years | Indefinite | Yes |

#### Anomaly Detection Triggers

The audit system MUST trigger alerts for the following anomalies:

```go
// AnomalyDetector monitors audit stream for suspicious patterns
type AnomalyDetector struct {
    alertChannel     chan<- *SecurityAlert
    ruleEngine       *AnomalyRuleEngine
    baselineProfiles map[[32]byte]*AgentBaseline
}

// AnomalyTrigger defines conditions that trigger security alerts
type AnomalyTrigger struct {
    TriggerID        string
    Name             string
    Description      string
    Severity         AlertSeverity
    Condition        AnomalyCondition
    Threshold        float64
    Window           time.Duration
    CooldownPeriod   time.Duration
}

// Standard anomaly triggers
var StandardAnomalyTriggers = []AnomalyTrigger{
    {
        TriggerID:   "AUTH_FAILURE_BURST",
        Name:        "Authentication Failure Burst",
        Description: "Multiple authentication failures in short period",
        Severity:    AlertSeverityHigh,
        Condition:   ConditionCountExceeds,
        Threshold:   5,
        Window:      1 * time.Minute,
    },
    {
        TriggerID:   "PERMISSION_ESCALATION",
        Name:        "Permission Escalation Attempt",
        Description: "Agent attempting operations beyond capability scope",
        Severity:    AlertSeverityCritical,
        Condition:   ConditionCountExceeds,
        Threshold:   3,
        Window:      5 * time.Minute,
    },
    {
        TriggerID:   "UNUSUAL_DATA_ACCESS",
        Name:        "Unusual Data Access Volume",
        Description: "Data access volume significantly exceeds baseline",
        Severity:    AlertSeverityMedium,
        Condition:   ConditionDeviationExceeds,
        Threshold:   3.0, // 3 standard deviations
        Window:      1 * time.Hour,
    },
    {
        TriggerID:   "OFF_HOURS_ACTIVITY",
        Name:        "Off-Hours Activity",
        Description: "Agent active outside normal operating hours",
        Severity:    AlertSeverityLow,
        Condition:   ConditionTimeWindow,
        Threshold:   0,
        Window:      0, // Uses time-of-day check
    },
    {
        TriggerID:   "RAPID_CONTRACT_CREATION",
        Name:        "Rapid Contract Creation",
        Description: "Unusually high rate of contract creation",
        Severity:    AlertSeverityMedium,
        Condition:   ConditionRateExceeds,
        Threshold:   10,
        Window:      10 * time.Minute,
    },
    {
        TriggerID:   "PAYMENT_ANOMALY",
        Name:        "Payment Amount Anomaly",
        Description: "Payment amount significantly deviates from baseline",
        Severity:    AlertSeverityHigh,
        Condition:   ConditionDeviationExceeds,
        Threshold:   5.0, // 5 standard deviations
        Window:      24 * time.Hour,
    },
    {
        TriggerID:   "CROSS_AGENT_COLLUSION",
        Name:        "Potential Agent Collusion",
        Description: "Suspicious coordination pattern between agents",
        Severity:    AlertSeverityCritical,
        Condition:   ConditionPatternMatch,
        Threshold:   0.8, // Pattern confidence threshold
        Window:      1 * time.Hour,
    },
    {
        TriggerID:   "GEOGRAPHIC_ANOMALY",
        Name:        "Geographic Access Anomaly",
        Description: "Access from unexpected geographic location",
        Severity:    AlertSeverityMedium,
        Condition:   ConditionGeoAnomaly,
        Threshold:   0,
        Window:      0,
    },
}

// AlertSeverity defines alert priority levels
type AlertSeverity uint8

const (
    AlertSeverityLow      AlertSeverity = 1  // Informational
    AlertSeverityMedium   AlertSeverity = 2  // Investigation recommended
    AlertSeverityHigh     AlertSeverity = 3  // Immediate investigation
    AlertSeverityCritical AlertSeverity = 4  // Immediate action required
)
```

---

### Rate Limiting Per Agent

Rate limiting prevents abuse and ensures fair resource distribution across all agents.

#### Rate Limit Configuration

```go
// AgentRateLimits defines comprehensive rate limits per agent
type AgentRateLimits struct {
    // Request limits
    RequestsPerSecond    uint32            // Max requests per second
    RequestsPerMinute    uint32            // Max requests per minute
    RequestsPerHour      uint32            // Max requests per hour
    RequestsPerDay       uint32            // Max requests per day

    // Burst configuration
    BurstCapacity        uint32            // Maximum burst size
    BurstRefillRate      float64           // Tokens per second refill

    // Resource-specific limits
    RoomMessagesPerMinute  uint32          // Messages per minute per room
    ContractsPerHour       uint32          // Contract creations per hour
    TasksPerHour           uint32          // Task distributions per hour
    PaymentsPerHour        uint32          // Payment authorizations per hour

    // Data limits
    MaxBytesPerRequest     uint64          // Maximum request payload
    MaxBytesPerDay         uint64          // Maximum data transfer per day

    // Token limits
    MaxTokensPerDay        uint64          // Maximum tokens spent per day
    MaxSinglePayment       uint64          // Maximum single payment amount
}

// TrustBasedRateLimits defines limits by trust level
var TrustBasedRateLimits = map[TrustLevel]*AgentRateLimits{
    TrustLevelUntrusted: {
        RequestsPerSecond:     5,
        RequestsPerMinute:     100,
        RequestsPerHour:       1000,
        RequestsPerDay:        10000,
        BurstCapacity:         10,
        BurstRefillRate:       2.0,
        RoomMessagesPerMinute: 10,
        ContractsPerHour:      0,    // Not allowed
        TasksPerHour:          1,
        PaymentsPerHour:       0,    // Not allowed
        MaxBytesPerRequest:    64 * 1024,    // 64KB
        MaxBytesPerDay:        10 * 1024 * 1024, // 10MB
        MaxTokensPerDay:       10000,
        MaxSinglePayment:      0,    // Not allowed
    },
    TrustLevelTrusted: {
        RequestsPerSecond:     50,
        RequestsPerMinute:     1000,
        RequestsPerHour:       10000,
        RequestsPerDay:        100000,
        BurstCapacity:         100,
        BurstRefillRate:       20.0,
        RoomMessagesPerMinute: 60,
        ContractsPerHour:      20,
        TasksPerHour:          50,
        PaymentsPerHour:       100,
        MaxBytesPerRequest:    1024 * 1024,     // 1MB
        MaxBytesPerDay:        1024 * 1024 * 1024, // 1GB
        MaxTokensPerDay:       1000000,
        MaxSinglePayment:      100000,
    },
}
```

#### Per-Agent Quota Tracking

```go
// AgentQuotaTracker tracks usage against quotas
type AgentQuotaTracker struct {
    mu               sync.RWMutex
    agentUsage       map[[32]byte]*AgentUsage
    windowManager    *SlidingWindowManager
}

// AgentUsage tracks all usage metrics for an agent
type AgentUsage struct {
    AgentID            [32]byte
    TrustLevel         TrustLevel

    // Request counters (sliding windows)
    SecondWindow       *SlidingWindow
    MinuteWindow       *SlidingWindow
    HourWindow         *SlidingWindow
    DayWindow          *SlidingWindow

    // Resource-specific counters
    RoomMessageCounters  map[[32]byte]*SlidingWindow  // Per-room
    ContractCounter      *SlidingWindow
    TaskCounter          *SlidingWindow
    PaymentCounter       *SlidingWindow

    // Data transfer tracking
    BytesInToday         *atomic.Uint64
    BytesOutToday        *atomic.Uint64
    LastDayReset         time.Time

    // Token tracking
    TokensSpentToday     *atomic.Uint64
    LastTokenReset       time.Time

    // Burst bucket
    BurstBucket          *TokenBucket
}

// CheckAndConsume verifies quota and consumes if allowed
func (t *AgentQuotaTracker) CheckAndConsume(
    agentID [32]byte,
    operation OperationType,
    resourceID [32]byte,
    bytes uint64,
) error {
    t.mu.Lock()
    defer t.mu.Unlock()

    usage := t.getOrCreateUsage(agentID)
    limits := TrustBasedRateLimits[usage.TrustLevel]

    // Check burst bucket first
    if !usage.BurstBucket.TryConsume(1) {
        return ErrBurstLimitExceeded{
            AgentID:  agentID,
            Capacity: limits.BurstCapacity,
        }
    }

    // Check sliding window limits
    if !usage.SecondWindow.TryIncrement(limits.RequestsPerSecond) {
        return ErrRateLimitExceeded{
            AgentID:  agentID,
            Window:   "second",
            Limit:    limits.RequestsPerSecond,
            Current:  usage.SecondWindow.Count(),
        }
    }

    if !usage.MinuteWindow.TryIncrement(limits.RequestsPerMinute) {
        return ErrRateLimitExceeded{
            AgentID:  agentID,
            Window:   "minute",
            Limit:    limits.RequestsPerMinute,
            Current:  usage.MinuteWindow.Count(),
        }
    }

    // Check operation-specific limits
    switch operation {
    case OpTypeSendMessage:
        roomCounter := usage.getRoomMessageCounter(resourceID)
        if !roomCounter.TryIncrement(limits.RoomMessagesPerMinute) {
            return ErrRoomMessageLimitExceeded{
                AgentID: agentID,
                RoomID:  resourceID,
                Limit:   limits.RoomMessagesPerMinute,
            }
        }
    case OpTypeCreateContract:
        if !usage.ContractCounter.TryIncrement(limits.ContractsPerHour) {
            return ErrContractLimitExceeded{
                AgentID: agentID,
                Limit:   limits.ContractsPerHour,
            }
        }
    case OpTypeAuthorizePayment:
        if !usage.PaymentCounter.TryIncrement(limits.PaymentsPerHour) {
            return ErrPaymentLimitExceeded{
                AgentID: agentID,
                Limit:   limits.PaymentsPerHour,
            }
        }
    }

    // Check data limits
    newTotal := usage.BytesOutToday.Add(bytes)
    if newTotal > limits.MaxBytesPerDay {
        usage.BytesOutToday.Add(-bytes) // Rollback
        return ErrDailyDataLimitExceeded{
            AgentID: agentID,
            Limit:   limits.MaxBytesPerDay,
            Used:    newTotal - bytes,
        }
    }

    return nil
}
```

#### Rate Limit Escalation

Rate limit violations trigger escalating consequences:

| Violation Count (24h) | Consequence | Duration |
|----------------------|-------------|----------|
| 1-5 | Warning logged | N/A |
| 6-20 | 50% rate reduction | 1 hour |
| 21-50 | 75% rate reduction | 6 hours |
| 51-100 | 90% rate reduction | 24 hours |
| >100 | Temporary suspension | 48 hours |

```go
// RateLimitEscalator manages violation escalation
type RateLimitEscalator struct {
    mu              sync.RWMutex
    violationCounts map[[32]byte]*ViolationRecord
}

// ViolationRecord tracks agent violations
type ViolationRecord struct {
    AgentID          [32]byte
    ViolationsToday  uint32
    LastViolation    time.Time
    CurrentPenalty   RatePenalty
    PenaltyExpires   time.Time
    History          []ViolationEvent
}

// RatePenalty defines penalty levels
type RatePenalty uint8

const (
    RatePenaltyNone       RatePenalty = 0
    RatePenaltyWarning    RatePenalty = 1  // No rate change
    RatePenaltyMild       RatePenalty = 2  // 50% reduction
    RatePenaltyModerate   RatePenalty = 3  // 75% reduction
    RatePenaltySevere     RatePenalty = 4  // 90% reduction
    RatePenaltySuspension RatePenalty = 5  // Complete block
)

// RecordViolation records a rate limit violation and returns updated penalty
func (e *RateLimitEscalator) RecordViolation(
    agentID [32]byte,
    violationType string,
) (*ViolationRecord, error) {
    e.mu.Lock()
    defer e.mu.Unlock()

    record := e.getOrCreateRecord(agentID)

    // Reset daily count if new day
    if time.Since(record.LastViolation) > 24*time.Hour {
        record.ViolationsToday = 0
    }

    record.ViolationsToday++
    record.LastViolation = time.Now()
    record.History = append(record.History, ViolationEvent{
        Timestamp: time.Now(),
        Type:      violationType,
    })

    // Determine new penalty
    oldPenalty := record.CurrentPenalty
    record.CurrentPenalty = e.calculatePenalty(record.ViolationsToday)
    record.PenaltyExpires = e.calculatePenaltyExpiry(record.CurrentPenalty)

    // Log escalation
    if record.CurrentPenalty > oldPenalty {
        logPenaltyEscalation(agentID, oldPenalty, record.CurrentPenalty)
    }

    return record, nil
}

// calculatePenalty determines penalty based on violation count
func (e *RateLimitEscalator) calculatePenalty(violations uint32) RatePenalty {
    switch {
    case violations <= 5:
        return RatePenaltyWarning
    case violations <= 20:
        return RatePenaltyMild
    case violations <= 50:
        return RatePenaltyModerate
    case violations <= 100:
        return RatePenaltySevere
    default:
        return RatePenaltySuspension
    }
}

// GetEffectiveLimits returns rate limits adjusted for any active penalty
func (e *RateLimitEscalator) GetEffectiveLimits(
    agentID [32]byte,
    baseLimits *AgentRateLimits,
) *AgentRateLimits {
    e.mu.RLock()
    defer e.mu.RUnlock()

    record, exists := e.violationCounts[agentID]
    if !exists || time.Now().After(record.PenaltyExpires) {
        return baseLimits
    }

    multiplier := e.getPenaltyMultiplier(record.CurrentPenalty)

    return &AgentRateLimits{
        RequestsPerSecond:     uint32(float64(baseLimits.RequestsPerSecond) * multiplier),
        RequestsPerMinute:     uint32(float64(baseLimits.RequestsPerMinute) * multiplier),
        RequestsPerHour:       uint32(float64(baseLimits.RequestsPerHour) * multiplier),
        RequestsPerDay:        uint32(float64(baseLimits.RequestsPerDay) * multiplier),
        BurstCapacity:         uint32(float64(baseLimits.BurstCapacity) * multiplier),
        // ... apply to all limits
    }
}

func (e *RateLimitEscalator) getPenaltyMultiplier(penalty RatePenalty) float64 {
    switch penalty {
    case RatePenaltyWarning:
        return 1.0
    case RatePenaltyMild:
        return 0.5
    case RatePenaltyModerate:
        return 0.25
    case RatePenaltySevere:
        return 0.1
    case RatePenaltySuspension:
        return 0.0
    default:
        return 1.0
    }
}
```

---

### Agent Revocation Procedures

Agent revocation provides mechanisms to immediately terminate rogue or compromised agent access.

#### Revocation Types

| Revocation Type | Scope | Reversible | Authority |
|-----------------|-------|------------|-----------|
| Soft Revocation | Single capability | Yes | Agent owner |
| Hard Revocation | All capabilities | Yes (with approval) | Agent owner or CA |
| Emergency Revocation | Complete termination | No | CA pool (threshold) |
| Owner Revocation | All agent's agents | Yes | Node owner |

```go
// RevocationType defines the scope and permanence of revocation
type RevocationType uint8

const (
    RevocationTypeSoft      RevocationType = 1  // Capability-specific
    RevocationTypeHard      RevocationType = 2  // All capabilities
    RevocationTypeEmergency RevocationType = 3  // Immediate, complete
    RevocationTypeOwner     RevocationType = 4  // Owner-initiated
)

// AgentRevocation represents a revocation record
type AgentRevocation struct {
    RevocationID     [32]byte
    AgentID          [32]byte
    Type             RevocationType

    // Scope
    RevokedCapabilities []CapabilityType   // For soft revocation

    // Authority
    RevokedBy          [32]byte            // Revoking entity ID
    RevokerType        RevokerType         // owner, ca, governance

    // Reason
    ReasonCode         RevocationReason
    ReasonDescription  string
    Evidence           []EvidenceRecord

    // Timing
    EffectiveAt        time.Time
    ExpiresAt          *time.Time          // nil for permanent
    GracePeriod        time.Duration

    // Status
    Status             RevocationStatus

    // Signatures
    RevokerSignature   []byte
    CASignature        []byte              // For hard/emergency revocations
}

// RevocationReason categorizes revocation causes
type RevocationReason uint8

const (
    RevocationReasonOwnerRequest    RevocationReason = 1   // Owner-initiated
    RevocationReasonViolation       RevocationReason = 2   // Policy violation
    RevocationReasonCompromise      RevocationReason = 3   // Security compromise
    RevocationReasonExpired         RevocationReason = 4   // Certificate expired
    RevocationReasonAbuseDetected   RevocationReason = 5   // Abuse pattern
    RevocationReasonGovernance      RevocationReason = 6   // Governance decision
)
```

#### Revocation Propagation

```
+------------------+     +------------------+     +------------------+
|    Revoking      |     |   DHT Network    |     |   Participating  |
|    Authority     |     |                  |     |      Nodes       |
+--------+---------+     +--------+---------+     +--------+---------+
         |                        |                        |
         | 1. REVOCATION REQUEST  |                        |
         |----------------------->|                        |
         | - Signed revocation    |                        |
         | - Evidence (if any)    |                        |
         |                        |                        |
         |                        | 2. VALIDATE & STORE    |
         |                        | - Verify signatures    |
         |                        | - Store in revocation  |
         |                        |   index                |
         |                        |                        |
         |                        | 3. PROPAGATE           |
         |                        |----------------------->|
         |                        | - Gossip protocol      |
         |                        | - Priority propagation |
         |                        |                        |
         |                        |                        | 4. LOCAL ENFORCEMENT
         |                        |                        | - Block agent access
         |                        |                        | - Terminate sessions
         |                        |                        | - Update caches
         |                        |                        |
         |<-----------------------|<-----------------------|
         | 5. CONFIRMATION        |                        |
         |    - Propagation       |                        |
         |      status            |                        |
+--------+---------+     +--------+---------+     +--------+---------+
```

#### Revocation Processing

```go
// RevocationService handles agent revocation
type RevocationService struct {
    dht               DHT
    revocationIndex   *RevocationIndex
    propagator        *RevocationPropagator
    sessionManager    *SessionManager
}

// RevokeAgent initiates agent revocation
func (s *RevocationService) RevokeAgent(
    ctx context.Context,
    revocation *AgentRevocation,
) error {
    // 1. Validate revocation request
    if err := s.validateRevocationRequest(revocation); err != nil {
        return ErrInvalidRevocationRequest{Cause: err}
    }

    // 2. Verify authority
    if err := s.verifyRevocationAuthority(ctx, revocation); err != nil {
        return ErrUnauthorizedRevocation{Cause: err}
    }

    // 3. Generate revocation ID
    revocation.RevocationID = s.generateRevocationID(revocation)

    // 4. Store in revocation index
    if err := s.revocationIndex.Store(revocation); err != nil {
        return ErrRevocationStoreFailed{Cause: err}
    }

    // 5. Store in DHT
    revKey := fmt.Sprintf("revocation:%x", revocation.AgentID)
    if err := s.dht.Put(ctx, revKey, serializeRevocation(revocation)); err != nil {
        return ErrDHTStoreFailed{Cause: err}
    }

    // 6. Terminate active sessions immediately (no grace period for emergency)
    if revocation.Type == RevocationTypeEmergency {
        s.sessionManager.TerminateAgentSessions(revocation.AgentID)
    } else {
        // Schedule termination after grace period
        s.scheduleSessionTermination(revocation)
    }

    // 7. Propagate revocation
    if err := s.propagator.Propagate(ctx, revocation); err != nil {
        // Log but don't fail - local enforcement is primary
        logPropagationWarning(revocation.RevocationID, err)
    }

    // 8. Log audit event
    s.logRevocationEvent(revocation)

    return nil
}

// IsRevoked checks if an agent is currently revoked
func (s *RevocationService) IsRevoked(
    ctx context.Context,
    agentID [32]byte,
) (bool, *AgentRevocation, error) {
    // Check local index first
    if revocation := s.revocationIndex.Get(agentID); revocation != nil {
        if s.isRevocationActive(revocation) {
            return true, revocation, nil
        }
    }

    // Check DHT for distributed consistency
    revKey := fmt.Sprintf("revocation:%x", agentID)
    data, err := s.dht.Get(ctx, revKey)
    if err != nil {
        if isNotFoundError(err) {
            return false, nil, nil
        }
        return false, nil, err
    }

    revocation, err := deserializeRevocation(data)
    if err != nil {
        return false, nil, err
    }

    // Update local index
    s.revocationIndex.Store(revocation)

    return s.isRevocationActive(revocation), revocation, nil
}
```

#### Grace Period Handling

```go
// GracePeriodManager handles revocation grace periods
type GracePeriodManager struct {
    scheduler        *time.Timer
    pendingActions   map[[32]byte]*GracePeriodAction
    mu               sync.Mutex
}

// GracePeriodAction defines action to take after grace period
type GracePeriodAction struct {
    RevocationID     [32]byte
    AgentID          [32]byte
    Action           GraceAction
    ExecuteAt        time.Time
    Notified         bool
}

// GraceAction defines what happens after grace period
type GraceAction uint8

const (
    GraceActionTerminateSessions  GraceAction = 1
    GraceActionBlockAccess        GraceAction = 2
    GraceActionArchiveData        GraceAction = 3
)

// Default grace periods by revocation type
var DefaultGracePeriods = map[RevocationType]time.Duration{
    RevocationTypeSoft:      1 * time.Hour,
    RevocationTypeHard:      15 * time.Minute,
    RevocationTypeEmergency: 0,                    // No grace period
    RevocationTypeOwner:     30 * time.Minute,
}

// ScheduleGracePeriodAction schedules action after grace period
func (m *GracePeriodManager) ScheduleGracePeriodAction(
    revocation *AgentRevocation,
) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    gracePeriod := revocation.GracePeriod
    if gracePeriod == 0 {
        gracePeriod = DefaultGracePeriods[revocation.Type]
    }

    action := &GracePeriodAction{
        RevocationID: revocation.RevocationID,
        AgentID:      revocation.AgentID,
        Action:       GraceActionTerminateSessions,
        ExecuteAt:    time.Now().Add(gracePeriod),
    }

    m.pendingActions[revocation.RevocationID] = action

    // Send warning notification to agent
    if gracePeriod > 0 {
        m.notifyAgent(revocation.AgentID, gracePeriod)
        action.Notified = true
    }

    // Schedule execution
    time.AfterFunc(gracePeriod, func() {
        m.executeGracePeriodAction(action)
    })

    return nil
}

// executeGracePeriodAction executes the scheduled action
func (m *GracePeriodManager) executeGracePeriodAction(action *GracePeriodAction) {
    m.mu.Lock()
    defer m.mu.Unlock()

    delete(m.pendingActions, action.RevocationID)

    switch action.Action {
    case GraceActionTerminateSessions:
        m.sessionManager.TerminateAgentSessions(action.AgentID)
    case GraceActionBlockAccess:
        m.accessController.BlockAgent(action.AgentID)
    case GraceActionArchiveData:
        m.dataArchiver.ArchiveAgentData(action.AgentID)
    }

    logGracePeriodActionExecuted(action)
}
```

---

### Cross-Agent Communication Security

Secure communication between agents ensures message integrity, authenticity, and confidentiality.

#### Agent-to-Agent Message Signing

All inter-agent messages MUST be cryptographically signed:

```go
// AgentMessage represents a signed message between agents
type AgentMessage struct {
    MessageID        [32]byte              // Unique message identifier

    // Routing
    SenderAgentID    [32]byte
    RecipientAgentID [32]byte

    // Content
    ContentType      string                // MIME type
    Payload          []byte                // Encrypted payload

    // Security
    Nonce            [24]byte              // For replay protection
    Timestamp        time.Time             // Message creation time
    ExpiresAt        time.Time             // Message expiration

    // Signatures
    SenderSignature  []byte                // Ed25519 signature from sender

    // Optional encryption
    Encrypted        bool
    EncryptionAlgo   string                // "X25519-ChaCha20-Poly1305"
    EphemeralPubKey  []byte                // For key agreement
}

// SignMessage signs a message with the sender's key
func SignMessage(
    msg *AgentMessage,
    senderPrivKey ed25519.PrivateKey,
) error {
    // Generate message ID
    msg.MessageID = generateMessageID(msg)

    // Set timestamp
    msg.Timestamp = time.Now().UTC()

    // Generate nonce for replay protection
    if _, err := io.ReadFull(rand.Reader, msg.Nonce[:]); err != nil {
        return ErrNonceGeneration{Cause: err}
    }

    // Create signing payload
    sigPayload := createSigningPayload(msg)

    // Sign
    msg.SenderSignature = ed25519.Sign(senderPrivKey, sigPayload)

    return nil
}

// VerifyMessageSignature verifies message authenticity
func VerifyMessageSignature(
    msg *AgentMessage,
    senderPubKey ed25519.PublicKey,
) error {
    // Verify sender signature
    sigPayload := createSigningPayload(msg)
    if !ed25519.Verify(senderPubKey, sigPayload, msg.SenderSignature) {
        return ErrInvalidMessageSignature
    }

    // Verify timestamp freshness
    age := time.Since(msg.Timestamp)
    if age > 5*time.Minute {
        return ErrMessageExpired{Age: age}
    }

    // Verify not in future
    if msg.Timestamp.After(time.Now().Add(30 * time.Second)) {
        return ErrMessageFromFuture
    }

    return nil
}

// createSigningPayload creates canonical payload for signing
func createSigningPayload(msg *AgentMessage) []byte {
    var buf bytes.Buffer

    // Include all fields except signature in deterministic order
    buf.Write(msg.SenderAgentID[:])
    buf.Write(msg.RecipientAgentID[:])
    buf.WriteString(msg.ContentType)
    buf.Write(msg.Payload)
    buf.Write(msg.Nonce[:])
    binary.Write(&buf, binary.BigEndian, msg.Timestamp.UnixNano())
    binary.Write(&buf, binary.BigEndian, msg.ExpiresAt.UnixNano())

    return buf.Bytes()
}
```

#### Channel Authentication

Authenticated channels between agents provide ongoing communication security:

```go
// AgentChannel represents an authenticated communication channel
type AgentChannel struct {
    ChannelID        [32]byte

    // Participants
    InitiatorAgent   [32]byte
    ResponderAgent   [32]byte

    // Session keys (derived via X25519)
    SendKey          [32]byte              // Key for outgoing messages
    ReceiveKey       [32]byte              // Key for incoming messages

    // State
    InitiatorCounter *atomic.Uint64        // Nonce counter for initiator
    ResponderCounter *atomic.Uint64        // Nonce counter for responder

    // Lifecycle
    EstablishedAt    time.Time
    ExpiresAt        time.Time
    LastActivity     time.Time

    // Authentication proof
    InitiatorProof   *ChannelAuthProof
    ResponderProof   *ChannelAuthProof
}

// ChannelAuthProof proves agent identity for channel
type ChannelAuthProof struct {
    AgentID          [32]byte
    EphemeralPubKey  [32]byte              // X25519 public key
    Timestamp        time.Time
    CapabilityToken  [32]byte              // Token authorizing communication
    Signature        []byte                // Agent signature over proof
}

// EstablishChannel creates authenticated channel between agents
func EstablishChannel(
    ctx context.Context,
    initiator *AgentIdentity,
    responderID [32]byte,
) (*AgentChannel, error) {
    // 1. Generate ephemeral X25519 keypair
    initiatorPriv, initiatorPub, err := generateX25519Keypair()
    if err != nil {
        return nil, ErrKeyGeneration{Cause: err}
    }

    // 2. Create auth proof
    initiatorProof := &ChannelAuthProof{
        AgentID:         initiator.AgentID,
        EphemeralPubKey: initiatorPub,
        Timestamp:       time.Now().UTC(),
    }

    // Sign proof
    proofBytes := serializeChannelAuthProof(initiatorProof)
    initiatorProof.Signature, err = sign(initiator.PrivateKey, proofBytes)
    if err != nil {
        return nil, ErrProofSigning{Cause: err}
    }

    // 3. Send channel request to responder
    request := &ChannelRequest{
        Type:           ChannelRequestTypeEstablish,
        InitiatorProof: initiatorProof,
    }

    response, err := sendChannelRequest(ctx, responderID, request)
    if err != nil {
        return nil, ErrChannelRequestFailed{Cause: err}
    }

    // 4. Verify responder's proof
    if err := verifyChannelAuthProof(response.ResponderProof); err != nil {
        return nil, ErrInvalidResponderProof{Cause: err}
    }

    // 5. Derive shared secret via X25519
    sharedSecret, err := x25519.X25519(initiatorPriv, response.ResponderProof.EphemeralPubKey[:])
    if err != nil {
        return nil, ErrKeyDerivation{Cause: err}
    }

    // 6. Derive session keys using HKDF
    sendKey, receiveKey := deriveSessionKeys(sharedSecret, initiatorProof, response.ResponderProof)

    // 7. Create channel
    channel := &AgentChannel{
        ChannelID:        generateChannelID(initiatorProof, response.ResponderProof),
        InitiatorAgent:   initiator.AgentID,
        ResponderAgent:   responderID,
        SendKey:          sendKey,
        ReceiveKey:       receiveKey,
        InitiatorCounter: &atomic.Uint64{},
        ResponderCounter: &atomic.Uint64{},
        EstablishedAt:    time.Now(),
        ExpiresAt:        time.Now().Add(24 * time.Hour),
        LastActivity:     time.Now(),
        InitiatorProof:   initiatorProof,
        ResponderProof:   response.ResponderProof,
    }

    return channel, nil
}
```

#### Replay Protection

Replay protection ensures messages cannot be replayed by attackers:

```go
// ReplayProtector prevents message replay attacks
type ReplayProtector struct {
    mu              sync.RWMutex
    seenNonces      map[[32]byte]*NonceRecord
    cleanupInterval time.Duration
}

// NonceRecord tracks a seen nonce
type NonceRecord struct {
    Nonce       [24]byte
    SenderID    [32]byte
    SeenAt      time.Time
    ExpiresAt   time.Time
}

// CheckAndRecordNonce verifies nonce hasn't been seen and records it
func (p *ReplayProtector) CheckAndRecordNonce(
    nonce [24]byte,
    senderID [32]byte,
    messageTimestamp time.Time,
) error {
    p.mu.Lock()
    defer p.mu.Unlock()

    // Create lookup key from nonce and sender
    lookupKey := p.createLookupKey(nonce, senderID)

    // Check if already seen
    if _, exists := p.seenNonces[lookupKey]; exists {
        return ErrReplayDetected{
            Nonce:    nonce,
            SenderID: senderID,
        }
    }

    // Verify message timestamp is reasonable
    age := time.Since(messageTimestamp)
    if age > 5*time.Minute {
        return ErrMessageTooOld{Age: age}
    }
    if age < -30*time.Second {
        return ErrMessageFromFuture{Offset: -age}
    }

    // Record nonce
    p.seenNonces[lookupKey] = &NonceRecord{
        Nonce:     nonce,
        SenderID:  senderID,
        SeenAt:    time.Now(),
        ExpiresAt: time.Now().Add(10 * time.Minute), // Keep for 10 minutes
    }

    return nil
}

// Cleanup removes expired nonces
func (p *ReplayProtector) Cleanup() {
    p.mu.Lock()
    defer p.mu.Unlock()

    now := time.Now()
    for key, record := range p.seenNonces {
        if now.After(record.ExpiresAt) {
            delete(p.seenNonces, key)
        }
    }
}

// MessageSequencer enforces message ordering within channels
type MessageSequencer struct {
    mu               sync.RWMutex
    channelSequences map[[32]byte]*SequenceState
}

// SequenceState tracks sequence numbers for a channel
type SequenceState struct {
    ChannelID        [32]byte
    LastSeenSeq      uint64
    WindowBitmap     uint64               // Sliding window for out-of-order
    WindowStart      uint64
}

// ValidateSequence checks message sequence number
func (s *MessageSequencer) ValidateSequence(
    channelID [32]byte,
    sequenceNum uint64,
) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    state := s.getOrCreateState(channelID)

    // Check if sequence is too old (before window)
    if sequenceNum < state.WindowStart {
        return ErrSequenceTooOld{
            Sequence:    sequenceNum,
            WindowStart: state.WindowStart,
        }
    }

    // Check if sequence is within window
    windowOffset := sequenceNum - state.WindowStart
    if windowOffset < 64 {
        // Check if already received
        if state.WindowBitmap&(1<<windowOffset) != 0 {
            return ErrDuplicateSequence{Sequence: sequenceNum}
        }
        // Mark as received
        state.WindowBitmap |= 1 << windowOffset
    } else {
        // Sequence is ahead of window, slide window
        shift := windowOffset - 63
        if shift > 64 {
            state.WindowBitmap = 0
        } else {
            state.WindowBitmap >>= shift
        }
        state.WindowStart = sequenceNum - 63
        state.WindowBitmap |= 1 << 63
    }

    if sequenceNum > state.LastSeenSeq {
        state.LastSeenSeq = sequenceNum
    }

    return nil
}
```

#### End-to-End Encryption

For sensitive communications, agents can establish end-to-end encrypted channels:

```go
// E2EEncryptor provides end-to-end encryption for agent messages
type E2EEncryptor struct {
    localAgentID     [32]byte
    localPrivateKey  [32]byte              // X25519 private key
    channelKeys      map[[32]byte]*ChannelKeys
    mu               sync.RWMutex
}

// ChannelKeys holds encryption keys for a channel
type ChannelKeys struct {
    ChannelID        [32]byte
    PeerAgentID      [32]byte
    SendKey          [32]byte
    ReceiveKey       [32]byte
    SendNonce        *atomic.Uint64
    ReceiveNonce     uint64
    EstablishedAt    time.Time
    ExpiresAt        time.Time
}

// EncryptMessage encrypts a message for the recipient
func (e *E2EEncryptor) EncryptMessage(
    channelID [32]byte,
    plaintext []byte,
) (*EncryptedMessage, error) {
    e.mu.RLock()
    keys, exists := e.channelKeys[channelID]
    e.mu.RUnlock()

    if !exists {
        return nil, ErrChannelNotFound{ChannelID: channelID}
    }

    // Check key expiration
    if time.Now().After(keys.ExpiresAt) {
        return nil, ErrChannelExpired{ChannelID: channelID}
    }

    // Generate nonce from counter
    nonce := keys.SendNonce.Add(1)
    var nonceBytes [24]byte
    binary.BigEndian.PutUint64(nonceBytes[16:], nonce)

    // Encrypt with ChaCha20-Poly1305
    aead, err := chacha20poly1305.NewX(keys.SendKey[:])
    if err != nil {
        return nil, ErrCipherCreation{Cause: err}
    }

    ciphertext := aead.Seal(nil, nonceBytes[:], plaintext, nil)

    return &EncryptedMessage{
        ChannelID:  channelID,
        Nonce:      nonce,
        Ciphertext: ciphertext,
    }, nil
}

// DecryptMessage decrypts a message from the sender
func (e *E2EEncryptor) DecryptMessage(
    msg *EncryptedMessage,
) ([]byte, error) {
    e.mu.RLock()
    keys, exists := e.channelKeys[msg.ChannelID]
    e.mu.RUnlock()

    if !exists {
        return nil, ErrChannelNotFound{ChannelID: msg.ChannelID}
    }

    // Verify nonce is not replayed
    if msg.Nonce <= keys.ReceiveNonce {
        return nil, ErrNonceReplay{
            ReceivedNonce: msg.Nonce,
            ExpectedMin:   keys.ReceiveNonce + 1,
        }
    }

    // Reconstruct nonce bytes
    var nonceBytes [24]byte
    binary.BigEndian.PutUint64(nonceBytes[16:], msg.Nonce)

    // Decrypt with ChaCha20-Poly1305
    aead, err := chacha20poly1305.NewX(keys.ReceiveKey[:])
    if err != nil {
        return nil, ErrCipherCreation{Cause: err}
    }

    plaintext, err := aead.Open(nil, nonceBytes[:], msg.Ciphertext, nil)
    if err != nil {
        return nil, ErrDecryptionFailed{Cause: err}
    }

    // Update receive nonce
    e.mu.Lock()
    keys.ReceiveNonce = msg.Nonce
    e.mu.Unlock()

    return plaintext, nil
}
```


---

## Related Documents

- [01-system-overview.md](01-system-overview.md) - System architecture overview
- [03-security-trust.md](03-security-trust.md) - Security model and TPM trust
- [05-certificate-authority.md](05-certificate-authority.md) - Distributed CA and IDevID
- [07-currency-transactions.md](07-currency-transactions.md) - Token transactions and escrow
- [10-governance-economics.md](10-governance-economics.md) - Economic model and pricing

---

**Document Version:** 1.2
**Last Updated:** 2026-01-10
**Status:** FINAL DESIGN - Agent Trust Enforcement Specification Complete
**Revision History:**
- v1.2 (2026-01-10): Added comprehensive Agent Trust Enforcement Specification including identity verification, capability attestation, behavior audit trail, rate limiting, revocation procedures, and cross-agent communication security
- v1.1 (2026-01-10): Added FINAL DESIGN for agent trust enforcement, room access control, workload distribution fairness, and MCP security
- v1.0 (2026-01-08): Initial specification
