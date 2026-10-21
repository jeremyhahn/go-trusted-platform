# Organization Identity for Anti-Sybil Protections

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.
## Overview

Organization Identity addresses a critical vulnerability in the trusted DHT network: the current per-TPM owner model (`OwnerID = SHA256(IDevID pubkey)`) allows well-funded attackers to acquire multiple devices and effectively bypass the 10% single-owner CA pool limit. With FROST threshold at 33-40%, an attacker controlling 33-40 hardware TPMs could theoretically control certificate signing operations.

Organization Identity replaces the per-TPM ownership model with true organizational binding, ensuring that CA pool diversity constraints apply to real-world entities rather than individual devices.

> **Cross-References:**
> - Security and trust: [03-security-trust.md](03-security-trust.md) (TPM Tier Classification)
> - Certificate authority: [05-certificate-authority.md](05-certificate-authority.md) (CA Pool Selection)
> - Defense and reputation: [09-defense-reputation.md](09-defense-reputation.md) (Role Eligibility)
> - QuicBaaS schema: [24-quicbaas-schema.md](24-quicbaas-schema.md) (Organization State Storage)
> - Federation: [22-federation.md](22-federation.md) (Federated vs P2P Organization)
> - Constants reference: [00-CONSTANTS.md](00-CONSTANTS.md) (Organization Parameters)

---

## Organization Data Model

Organizations represent real-world entities (companies, individuals, foundations) that operate one or more nodes in the network.

### Schema Definition

```go
// OrganizationState represents a verified organization in the network
type OrganizationState struct {
    // Identity
    OrganizationID   [32]byte           `json:"organization_id"`   // Unique org identifier
    DisplayName      string             `json:"display_name"`      // Human-readable name
    VerificationType VerificationType   `json:"verification_type"` // domain or economic

    // Domain Verification (if applicable)
    Domain           string             `json:"domain,omitempty"`           // Verified domain
    DomainChallenge  string             `json:"domain_challenge,omitempty"` // Current challenge
    DomainVerifiedAt int64              `json:"domain_verified_at,omitempty"`
    DomainExpiresAt  int64              `json:"domain_expires_at,omitempty"`

    // Economic Verification (if applicable)
    StakeWalletID    [32]byte           `json:"stake_wallet_id,omitempty"`  // Controlling wallet
    StakeAmount      uint64             `json:"stake_amount,omitempty"`     // Coins staked
    StakeLockedUntil int64              `json:"stake_locked_until,omitempty"`
    StakeSlashable   bool               `json:"stake_slashable"`            // Can be slashed

    // Associated Nodes
    PrimaryNodeID    [32]byte           `json:"primary_node_id"`    // Primary contact node
    AssociatedNodes  [][32]byte         `json:"associated_nodes"`   // All org nodes
    CAPoolNodes      int                `json:"ca_pool_nodes"`      // Nodes in CA pool

    // Reputation and Standing
    OrgReputation    float64            `json:"org_reputation"`     // Organization-level rep (0.0-1.0)
    ActiveSince      int64              `json:"active_since"`       // First verification timestamp
    LastActivity     int64              `json:"last_activity"`      // Last org activity
    Status           OrgStatus          `json:"status"`             // active, suspended, terminated

    // Audit Trail
    History          []OrgEvent         `json:"history"`            // Significant events
    Version          uint64             `json:"version"`            // Optimistic concurrency
    UpdatedAt        int64              `json:"updated_at"`         // Last modification
}

// VerificationType indicates how the organization was verified
type VerificationType uint8

const (
    VerificationTypeDomain   VerificationType = iota // DNS TXT record verification
    VerificationTypeEconomic                         // Stake-based verification
)

// OrgStatus represents the organization's current standing
type OrgStatus uint8

const (
    OrgStatusActive    OrgStatus = iota // Verified and in good standing
    OrgStatusPending                    // Verification in progress
    OrgStatusSuspended                  // Temporarily suspended (investigation)
    OrgStatusTerminated                 // Permanently removed
)

// OrgEvent records significant organization lifecycle events
type OrgEvent struct {
    EventType   OrgEventType `json:"event_type"`
    Timestamp   int64        `json:"timestamp"`
    Details     string       `json:"details"`
    NodeID      [32]byte     `json:"node_id,omitempty"`      // Related node if applicable
    Amount      uint64       `json:"amount,omitempty"`        // Related amount if applicable
    PerformedBy [32]byte     `json:"performed_by,omitempty"` // Who initiated
}

// OrgEventType categorizes organization events
type OrgEventType uint8

const (
    OrgEventCreated         OrgEventType = iota // Organization registered
    OrgEventDomainVerified                      // Domain verification completed
    OrgEventStakeDeposited                      // Economic stake deposited
    OrgEventStakeSlashed                        // Stake slashed for misconduct
    OrgEventNodeAdded                           // Node associated with org
    OrgEventNodeRemoved                         // Node disassociated
    OrgEventRenewal                             // Verification renewed
    OrgEventSuspended                           // Org suspended
    OrgEventReinstated                          // Org reinstated after suspension
    OrgEventTerminated                          // Org permanently terminated
)
```

**DHT Key:** `org:{organization-id}`

### Organization ID Generation

Organization IDs are deterministically derived based on verification method:

| Verification Type | ID Formula | Properties |
|-------------------|------------|------------|
| Domain | `SHA256(domain + IDevID_fingerprint)` | Unique per domain + device combo |
| Economic | `SHA256(wallet_id)` | Unique per stake wallet |

```go
// GenerateOrganizationID creates the organization identifier
func GenerateOrganizationID(vt VerificationType, data []byte) [32]byte {
    switch vt {
    case VerificationTypeDomain:
        // data = domain || IDevID_fingerprint
        return sha256.Sum256(data)
    case VerificationTypeEconomic:
        // data = wallet_id
        return sha256.Sum256(data)
    default:
        panic("invalid verification type")
    }
}
```

---

## Domain Verification Protocol

Domain verification provides free organization identity verification by proving control over a DNS domain.

### Protocol Overview

```
+------------------+                              +------------------+
|  Operator Node   |                              |   DHT Network    |
+------------------+                              +------------------+
        |                                                  |
        | 1. Request domain verification                   |
        |------------------------------------------------->|
        |                                                  |
        |    2. Generate challenge + nonce                 |
        |<-------------------------------------------------|
        |                                                  |
        | 3. Set DNS TXT record                            |
        |    _trusted-platform-org.example.com             |
        |                                                  |
        | 4. Submit verification request                   |
        |------------------------------------------------->|
        |                                                  |
        |    5. DNS lookup (multiple verifiers)            |
        |    6. Validate challenge + IDevID signature      |
        |    7. Consensus on verification result           |
        |                                                  |
        |    8. Organization registered (if valid)         |
        |<-------------------------------------------------|
        |                                                  |
```

### DNS TXT Record Format

```
_trusted-platform-org.example.com TXT "tp-verify=v1;chal=<challenge>;idevid=<fingerprint>;sig=<signature>"
```

| Field | Description | Example |
|-------|-------------|---------|
| `tp-verify` | Protocol version | `v1` |
| `chal` | Base64-encoded challenge from network | `dGVzdGNoYWxsZW5nZQ==` |
| `idevid` | SHA256 fingerprint of IDevID public key | `a1b2c3d4...` (64 hex chars) |
| `sig` | Base64-encoded signature over challenge | `MEUCIQ...` |

### Verification Process

```go
// DomainVerificationRequest initiates domain verification
type DomainVerificationRequest struct {
    Domain          string   `json:"domain"`           // Domain to verify
    NodeID          [32]byte `json:"node_id"`          // Requesting node
    IDevIDPublicKey []byte   `json:"idevid_public_key"` // IDevID public key
    Timestamp       int64    `json:"timestamp"`
    Signature       []byte   `json:"signature"`        // Node signature over request
}

// DomainChallenge issued by the network
type DomainChallenge struct {
    Domain        string   `json:"domain"`
    Challenge     [32]byte `json:"challenge"`      // Random 32-byte challenge
    IssuedAt      int64    `json:"issued_at"`
    ExpiresAt     int64    `json:"expires_at"`     // 24 hours from issuance
    VerifierNodes [][32]byte `json:"verifier_nodes"` // Assigned verifiers
}

// DomainVerificationResult from verifier consensus
type DomainVerificationResult struct {
    Domain           string             `json:"domain"`
    OrganizationID   [32]byte           `json:"organization_id"`
    VerificationStatus VerificationStatus `json:"status"`
    VerifierVotes    []VerifierVote     `json:"verifier_votes"`
    VerifiedAt       int64              `json:"verified_at,omitempty"`
    ExpiresAt        int64              `json:"expires_at,omitempty"` // 90 days
    FailureReason    string             `json:"failure_reason,omitempty"`
}
```

### Verification Parameters

| Parameter | Value | Description | Reference |
|-----------|-------|-------------|-----------|
| Challenge expiry | 24 hours | Time to complete DNS setup | 00-CONSTANTS.md |
| Verifier count | 5 | Number of independent verifiers | 00-CONSTANTS.md |
| Required consensus | 3/5 | Verifiers that must agree | 00-CONSTANTS.md |
| Verification validity | 90 days | Time until renewal required | 00-CONSTANTS.md |
| DNS propagation grace | 1 hour | Grace period for DNS propagation | 00-CONSTANTS.md |
| Retry attempts | 3 | Verification attempts allowed | 00-CONSTANTS.md |
| Retry cooldown | 4 hours | Wait between retry attempts | 00-CONSTANTS.md |

### Verification Steps

1. **Challenge Issuance**: Network generates random 32-byte challenge with 24-hour expiry
2. **DNS Record Setup**: Operator creates TXT record at `_trusted-platform-org.<domain>`
3. **Distributed Verification**: 5 verifier nodes independently query DNS
4. **Signature Validation**: Verifiers confirm signature over challenge matches IDevID
5. **Consensus**: 3/5 verifiers must agree for verification success
6. **Registration**: Organization registered with 90-day validity

---

## Economic Verification Protocol

Economic verification provides organization identity through staked coins, suitable for operators without domain names or preferring economic commitment.

### Stake Requirements

| Parameter | Value | Description |
|-----------|-------|-------------|
| Organization stake | 1,000 coins | One-time stake per organization |
| Lock duration | 180 days | Minimum lock period |
| Slashable | Yes | Can be forfeited for misconduct |

### Stake Deposit Process

```
+------------------+                              +------------------+
|  Operator Node   |                              |   DHT Network    |
+------------------+                              +------------------+
        |                                                  |
        | 1. Create stake transaction                      |
        |    - 1,000 coins to stake contract               |
        |    - IDevID signature required                   |
        |------------------------------------------------->|
        |                                                  |
        |    2. Transaction confirmed (consensus)          |
        |<-------------------------------------------------|
        |                                                  |
        | 3. Submit organization registration              |
        |    - Reference stake transaction                 |
        |    - IDevID signature                            |
        |------------------------------------------------->|
        |                                                  |
        |    4. Verify stake ownership                     |
        |    5. Lock stake for 180 days                    |
        |    6. Register organization                      |
        |                                                  |
        |    7. Organization active                        |
        |<-------------------------------------------------|
        |                                                  |
```

### Stake Schema

```go
// OrganizationStake represents a staked organization verification
type OrganizationStake struct {
    StakeID         [32]byte `json:"stake_id"`          // Unique stake identifier
    WalletID        [32]byte `json:"wallet_id"`         // Controlling wallet
    Amount          uint64   `json:"amount"`            // Staked amount (1000 coins)
    DepositTxID     [32]byte `json:"deposit_tx_id"`     // Original deposit transaction
    OrganizationID  [32]byte `json:"organization_id"`   // Linked organization

    // Lock Status
    LockedUntil     int64    `json:"locked_until"`      // Unlock timestamp
    IsSlashed       bool     `json:"is_slashed"`        // Has been slashed
    SlashedAmount   uint64   `json:"slashed_amount"`    // Amount slashed (if any)
    SlashReason     string   `json:"slash_reason"`      // Reason for slash

    // Timestamps
    CreatedAt       int64    `json:"created_at"`
    UpdatedAt       int64    `json:"updated_at"`
}

// StakeTransaction for organization registration
type StakeTransaction struct {
    TransactionID   [32]byte `json:"transaction_id"`
    FromWallet      [32]byte `json:"from_wallet"`
    Amount          uint64   `json:"amount"`
    Purpose         string   `json:"purpose"`           // "org_verification"
    IDevIDSignature []byte   `json:"idevid_signature"` // IDevID must control wallet
    Timestamp       int64    `json:"timestamp"`
}
```

### Economic vs Domain Comparison

| Aspect | Domain Verification | Economic Verification |
|--------|--------------------|-----------------------|
| Cost | Free | 1,000 coins (~$100-$1,000) |
| Requirements | Domain ownership | Coin holdings |
| Renewal | 90 days | 180 days (then unlock) |
| Slashable | No | Yes (misconduct) |
| Use case | Established organizations | Anonymous/pseudonymous operators |
| Speed | 1-24 hours (DNS propagation) | Minutes (transaction confirmation) |

---

## Organization Lifecycle

### State Transitions

```
                                    +------------+
                                    |  Pending   |
                                    | Verification|
                                    +-----+------+
                                          |
                           Verification   |   Verification
                           Success        |   Failed
                              +-----+-----+-----+-----+
                              |                       |
                              v                       v
                        +-----------+           +-----------+
                        |  Active   |           |  Rejected |
                        +-----------+           +-----------+
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
        +-----------+   +-----------+   +-----------+
        | Suspended |   |  Renewed  |   | Terminated|
        +-----------+   +-----------+   +-----------+
              |               |
              v               v
        +-----------+   +-----------+
        |Reinstated |   |  Active   |
        |  (Active) |   |           |
        +-----------+   +-----------+
```

### Lifecycle Stages

#### 1. Creation

Organizations are created through either verification path:

```go
// CreateOrganization initiates organization registration
func CreateOrganization(req OrganizationRequest) (*OrganizationState, error) {
    org := &OrganizationState{
        Status:       OrgStatusPending,
        ActiveSince:  time.Now().Unix(),
        OrgReputation: 0.0, // Organizations start at zero reputation
        History:      []OrgEvent{{
            EventType: OrgEventCreated,
            Timestamp: time.Now().Unix(),
            Details:   fmt.Sprintf("verification_type=%d", req.VerificationType),
        }},
    }

    switch req.VerificationType {
    case VerificationTypeDomain:
        org.OrganizationID = GenerateOrganizationID(
            VerificationTypeDomain,
            append([]byte(req.Domain), req.IDevIDFingerprint...),
        )
        org.Domain = req.Domain
    case VerificationTypeEconomic:
        org.OrganizationID = GenerateOrganizationID(
            VerificationTypeEconomic,
            req.WalletID[:],
        )
        org.StakeWalletID = req.WalletID
        org.StakeAmount = req.StakeAmount
    }

    return org, nil
}
```

#### 2. Renewal

| Verification Type | Renewal Period | Renewal Process |
|-------------------|----------------|-----------------|
| Domain | 90 days | Re-verify DNS TXT record |
| Economic | 180 days | Stake automatically unlocks; re-stake to continue |

```go
// RenewalConfig for organization verification
type RenewalConfig struct {
    DomainRenewalPeriod   time.Duration // 90 days
    EconomicRenewalPeriod time.Duration // 180 days
    RenewalGracePeriod    time.Duration // 14 days after expiry
    RenewalReminderDays   []int         // [30, 14, 7, 3, 1] days before expiry
}
```

**Renewal Notifications:**
- 30 days before expiry: First reminder
- 14 days before expiry: Second reminder
- 7 days before expiry: Warning
- 3 days before expiry: Urgent warning
- 1 day before expiry: Final notice

**Grace Period:** 14 days after expiry during which:
- Organization status changes to `Suspended`
- Nodes remain in network but CA pool participation paused
- Renewal completes instantly if verification succeeds

#### 3. Termination

Organizations may be terminated for:

| Reason | Trigger | Recovery |
|--------|---------|----------|
| Voluntary withdrawal | Operator request | Re-register after 30 days |
| Verification failure | Renewal not completed | Re-register after grace period |
| Misconduct | Byzantine behavior detected | Permanent ban (no recovery) |
| Stake slash (100%) | Severe violation | Permanent ban (no recovery) |

```go
// TerminateOrganization permanently removes an organization
func TerminateOrganization(orgID [32]byte, reason string, permanent bool) error {
    org, err := GetOrganization(orgID)
    if err != nil {
        return err
    }

    org.Status = OrgStatusTerminated
    org.History = append(org.History, OrgEvent{
        EventType: OrgEventTerminated,
        Timestamp: time.Now().Unix(),
        Details:   reason,
    })

    // Disassociate all nodes
    for _, nodeID := range org.AssociatedNodes {
        DisassociateNodeFromOrg(nodeID, orgID)
    }

    // Slash remaining stake if economic verification
    if org.VerificationType == VerificationTypeEconomic && permanent {
        SlashStake(org.StakeWalletID, org.StakeAmount, "org_termination")
    }

    return SaveOrganization(org)
}
```

---

## Multi-Node Organization Constraints

Organizations can operate multiple nodes, but CA pool participation is strictly limited to prevent single-entity dominance.

### CA Pool Limits (from 00-CONSTANTS.md)

| Constraint | Limit | Rationale |
|------------|-------|-----------|
| Max per organization | 5% of CA pool | Prevents single entity control |
| Min unique organizations | 20 | Ensures diversity (at maturity) |
| Per-node stake (base) | 100 coins | Economic commitment |
| Per-node stake (compounding) | 1.2x per additional node | Discourages excessive concentration |

### Compounding Stake Formula

For each additional node an organization adds to the CA pool, the stake requirement increases exponentially:

```go
// CalculateNodeStake returns required stake for nth node in CA pool
func CalculateNodeStake(nodeIndex int, baseStake uint64, compoundFactor float64) uint64 {
    // Node 1:  100 coins
    // Node 2:  120 coins (100 * 1.2)
    // Node 3:  144 coins (100 * 1.2^2)
    // Node 5:  207 coins (100 * 1.2^4)
    // Node 10: 516 coins (100 * 1.2^9)
    // Node 20: 3,834 coins (100 * 1.2^19)
    return uint64(float64(baseStake) * math.Pow(compoundFactor, float64(nodeIndex-1)))
}

// Example stake calculation for an organization:
// Node Index | Stake Required | Cumulative Total
//     1      |      100       |       100
//     2      |      120       |       220
//     3      |      144       |       364
//     4      |      173       |       537
//     5      |      207       |       744
//    ...     |      ...       |       ...
//    10      |      516       |     ~1,600
```

### Multi-Node Registration

```go
// AssociateNodeWithOrg links a node to an organization
func AssociateNodeWithOrg(nodeID [32]byte, orgID [32]byte) error {
    org, err := GetOrganization(orgID)
    if err != nil {
        return err
    }

    node, err := GetNode(nodeID)
    if err != nil {
        return err
    }

    // Verify IDevID ownership matches organization
    if !VerifyNodeOrgOwnership(node, org) {
        return ErrOwnershipMismatch
    }

    // Check if node already associated with another org
    if node.OrganizationID != [32]byte{} && node.OrganizationID != orgID {
        return ErrNodeAlreadyAssociated
    }

    // Add to organization
    org.AssociatedNodes = append(org.AssociatedNodes, nodeID)
    node.OrganizationID = orgID

    org.History = append(org.History, OrgEvent{
        EventType: OrgEventNodeAdded,
        Timestamp: time.Now().Unix(),
        NodeID:    nodeID,
    })

    return SaveOrganizationAndNode(org, node)
}
```

### CA Pool Entry with Organization

```go
// CAPoolEntry request with organization context
type CAPoolEntryRequest struct {
    NodeID         [32]byte `json:"node_id"`
    OrganizationID [32]byte `json:"organization_id"`
    StakeAmount    uint64   `json:"stake_amount"`     // Must meet compounding requirement
    StakeTxID      [32]byte `json:"stake_tx_id"`      // Proof of stake
    Timestamp      int64    `json:"timestamp"`
    Signature      []byte   `json:"signature"`
}

// ValidateCAPoolEntry checks organization constraints
func ValidateCAPoolEntry(req CAPoolEntryRequest, poolSize int) error {
    org, err := GetOrganization(req.OrganizationID)
    if err != nil {
        return err
    }

    // Check organization status
    if org.Status != OrgStatusActive {
        return ErrOrgNotActive
    }

    // Check 5% per-org limit
    maxOrgNodes := int(float64(poolSize) * 0.05)
    if org.CAPoolNodes >= maxOrgNodes {
        return ErrOrgCAPoolLimitReached
    }

    // Calculate required stake (compounding)
    nodeIndex := org.CAPoolNodes + 1
    requiredStake := CalculateNodeStake(nodeIndex, 100, 1.2)
    if req.StakeAmount < requiredStake {
        return ErrInsufficientStake
    }

    return nil
}
```

---

## Organization-Level Reputation

Organizations accumulate reputation independently of individual nodes, providing an aggregate trust signal.

### Organization Reputation Formula

```go
// CalculateOrgReputation computes aggregate organization reputation
func CalculateOrgReputation(org *OrganizationState) float64 {
    if len(org.AssociatedNodes) == 0 {
        return 0.0
    }

    var totalReputation float64
    var weightSum float64

    for _, nodeID := range org.AssociatedNodes {
        node, err := GetNode(nodeID)
        if err != nil {
            continue
        }

        // Weight by node age (older nodes weighted more heavily)
        age := time.Now().Unix() - node.JoinedAt
        weight := math.Min(float64(age)/(180*24*3600), 1.0) // Cap at 180 days

        totalReputation += node.Reputation * weight
        weightSum += weight
    }

    if weightSum == 0 {
        return 0.0
    }

    // Apply organization tenure factor
    orgAge := time.Now().Unix() - org.ActiveSince
    tenureFactor := math.Min(float64(orgAge)/(365*24*3600), 1.0) // Cap at 1 year

    baseReputation := totalReputation / weightSum
    return baseReputation * (0.7 + 0.3*tenureFactor) // 70% node rep, 30% tenure bonus
}
```

### Organization Reputation Events

| Event | Impact | Description |
|-------|--------|-------------|
| Node misconduct | -0.10 per incident | Individual node misbehavior affects org |
| Node excellence | +0.01 per month | Above-average node performance |
| CA participation | +0.02 per successful signing | Successful threshold signatures |
| Verification renewal | +0.01 | Timely renewal demonstrates commitment |
| Slashing event | -0.50 minimum | Any stake slashing severely impacts org rep |

### Organization Reputation Thresholds

| Org Reputation | Implications |
|----------------|--------------|
| 0.0 - 0.30 | New organization, limited capabilities |
| 0.30 - 0.60 | Established, nodes eligible for standard roles |
| 0.60 - 0.90 | Trusted, approaching CA pool eligibility |
| 0.90 - 1.0 | Highly trusted, nodes eligible for CA pool |

---

## CA Pool Implications

Organization identity fundamentally changes CA pool selection by applying diversity constraints at the organizational level.

### CA Pool Selection with Organization Constraints

```go
// CAPoolNetworkConstraints defines diversity requirements
type CAPoolNetworkConstraints struct {
    MaxPercentPerASN       float64  // 0.15 (15%)
    MinUniqueASNs          int      // 7
    MaxPercentPerSubnet24  float64  // 0.03 (3%)
    MaxNodesPerSubnet      int      // 5
    MaxPercentPerCountry   float64  // 0.25 (25%)
    MinCountries           int      // 3
    MaxPercentPerOrg       float64  // 0.05 (5%)
    MinUniqueOrgs          int      // 20
}

// SelectCAPool applies organization-aware selection
func SelectCAPool(candidates []NodeInfo, constraints CAPoolNetworkConstraints, targetSize int) ([]NodeInfo, error) {
    selected := make([]NodeInfo, 0, targetSize)
    orgCounts := make(map[[32]byte]int)
    asnCounts := make(map[string]int)

    // Sort by VRF output (randomized but deterministic)
    SortByVRFOutput(candidates)

    for _, candidate := range candidates {
        if len(selected) >= targetSize {
            break
        }

        // Check organization limit (5%)
        maxOrgNodes := int(float64(targetSize) * constraints.MaxPercentPerOrg)
        if orgCounts[candidate.OrganizationID] >= maxOrgNodes {
            continue // Skip - org already at limit
        }

        // Check ASN limit (15%)
        maxASNNodes := int(float64(targetSize) * constraints.MaxPercentPerASN)
        if asnCounts[candidate.ASN] >= maxASNNodes {
            continue // Skip - ASN already at limit
        }

        // Add to pool
        selected = append(selected, candidate)
        orgCounts[candidate.OrganizationID]++
        asnCounts[candidate.ASN]++
    }

    // Verify minimum diversity
    if len(orgCounts) < constraints.MinUniqueOrgs {
        return nil, ErrInsufficientOrgDiversity
    }
    if len(asnCounts) < constraints.MinUniqueASNs {
        return nil, ErrInsufficientASNDiversity
    }

    return selected, nil
}
```

### Attack Cost with Organization Identity

With organization identity in place, an attacker attempting to control 33% of the CA pool (threshold for FROST signing) must:

| Barrier | Requirement | Attack Cost |
|---------|-------------|-------------|
| Hardware TPMs | 33 discrete TPMs | ~$1,650 (33 x $50) |
| Organizations | 7+ orgs (5% limit each) | 7,000 coins or 7 domains |
| ASNs | 5+ ASNs (15% limit) | Global datacenter presence |
| Time | 120 days x 33 nodes | 10+ years aggregate node-time |
| Verifiers | 25 unique per node | 825 diverse verifications |
| Stakes | ~1,600 coins (10 nodes/org) | ~$160-$1,600 |

---

## Integration Points

### Node State Extension

The existing `NodeState` schema (see [24-quicbaas-schema.md](24-quicbaas-schema.md)) must include organization binding:

```go
// NodeState with Organization binding
type NodeState struct {
    // ... existing fields ...

    // Organization binding (new)
    OrganizationID  [32]byte `json:"organization_id"`   // Linked organization
    OrgJoinedAt     int64    `json:"org_joined_at"`     // When joined org
    OrgVerifiedBy   [32]byte `json:"org_verified_by"`   // Verifier node
}
```

### TPM Info Extension

TPM tier classification enables hardware-only CA pool enforcement:

```go
// TPMInfo with tier classification
type TPMInfo struct {
    // ... existing fields ...

    // TPM Tier (new)
    TPMTier TPMTier `json:"tpm_tier"` // hardware, firmware, cloud, platform
}

// TPMTier classifies TPM security level
type TPMTier uint8

const (
    TPMTierHardware TPMTier = 1 // Discrete TPM (CA pool eligible)
    TPMTierFirmware TPMTier = 2 // fTPM (infrastructure only)
    TPMTierCloud    TPMTier = 3 // vTPM (infrastructure only)
    TPMTierPlatform TPMTier = 4 // Platform-minted (backbone only)
)
```

### Reputation System Integration

Organization identity integrates with the reputation system (see [09-defense-reputation.md](09-defense-reputation.md)):

```go
// Enhanced CA eligibility check
func IsCAPoolEligible(node *NodeState, org *OrganizationState) bool {
    // Node requirements
    if node.Reputation < 0.90 {
        return false
    }
    if time.Now().Unix() - node.JoinedAt < 120*24*3600 { // 120 days
        return false
    }
    if node.TPMInfo.TPMTier != TPMTierHardware {
        return false
    }

    // Organization requirements
    if org.Status != OrgStatusActive {
        return false
    }
    if org.OrgReputation < 0.60 {
        return false
    }

    return true
}
```

### Federation Integration

For federated organizations (see [22-federation.md](22-federation.md)), organization identity operates at the federation level:

| Deployment | Organization Scope | Verification |
|------------|-------------------|--------------|
| P2P-only node | Network-verified org | Domain or economic |
| Federated org | Federation-verified org | Cross-certification |
| Hybrid | Both org types | Federation primary, P2P secondary |

---

## Security Considerations

### Domain Verification Security

| Threat | Mitigation |
|--------|------------|
| DNS spoofing | Multiple independent verifiers; DNSSEC preferred |
| Domain hijacking | IDevID signature binding; signature required in TXT record |
| Expired domain re-registration | Strict renewal; grace period limits |
| Subdomain attacks | Full domain verification only; no subdomain delegation |

### Economic Verification Security

| Threat | Mitigation |
|--------|------------|
| Stake-and-attack | 180-day lock; slashing for misconduct |
| Flash loan attacks | Lock duration prevents quick stake/unstake |
| Wallet compromise | Multi-sig recommended; IDevID binding |
| Sybil via multiple wallets | Compounding stake makes multiple orgs expensive |

### Organization Impersonation

| Threat | Mitigation |
|--------|------------|
| Claiming false org | Domain verification proves ownership |
| Organization spoofing | Organization ID cryptographically bound |
| Name confusion | Display names informational only; ID is canonical |

### CA Pool Attack Vectors

| Attack | Defense Provided |
|--------|------------------|
| Sybil (many devices) | Organization limits cap per-entity influence |
| Collusion | Behavioral monitoring detects coordination |
| Economic attack | Time + reputation + diversity make attacks expensive |
| Hardware attack | TPM tier enforcement; hardware-only for CA |

---

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0.0 | 2026-01-10 | Initial organization identity specification | Documentation Team |
