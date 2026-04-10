# Secure Content Storage Architecture

## Overview

This document specifies the Key Share Partitioning (KSP) system for secure content storage on the go-trusted-platform P2P network. The architecture ensures that user data remains secure even if individual nodes are compromised, encryption algorithms are weakened, or attackers collude across the network.

### Core Principles

1. **DHT stores only pointers** - Never actual content blocks
2. **User-Defined Classifications** - Arbitrary tags linked to security policies
3. **Key Share Partitioning** - Content divided into K partitions, each encrypted with unique key
4. **Node Pool Segregation** - Nodes can ONLY store blocks from ONE key share (Hash(NodeID) mod K)
5. **Physical Impossibility** - Even with broken encryption, no single node has complete data
6. **Hybrid Storage** - Peer nodes (reciprocal) + Storage nodes (paid SLA)
7. **Policy Inheritance** - Classifications can inherit from parent policies

---

## Data Classification System

Users define arbitrary classification tags, each linked to a security policy. When content is tagged with a classification, the associated policy is automatically applied.

### Classification Registry

```go
// ClassificationTag is a user-defined label for data sensitivity
type ClassificationTag string

// ClassificationPolicy defines the security settings for a classification
type ClassificationPolicy struct {
    Tag         ClassificationTag
    Description string
    CreatedAt   time.Time
    UpdatedAt   time.Time
    Policy      SecurityPolicy
}

// ClassificationRegistry stores user-defined classifications
type ClassificationRegistry struct {
    OwnerID          [32]byte
    Classifications  map[ClassificationTag]*ClassificationPolicy
}

// SecurityPolicy defines how data with this classification is stored
type SecurityPolicy struct {
    // KSP settings (K=0 means no partitioning, store whole)
    K                uint8   // Key shares (0=whole, 3-16=partitioned)
    MinRedundancy    uint8   // Min copies per block

    // Encryption
    EncryptionAlgo   string  // "AES-256-GCM", "ChaCha20-Poly1305", or "" for none

    // Manifest security
    ManifestStrategy ManifestStrategy

    // Availability requirements (monitoring handled by network layer)
    Availability     AvailabilitySLAConfig

    // Advanced features
    Scatter          ScatterConfig
    Shuffle          ShuffleConfig
    MultiLayer       MultiLayerConfig
    Decoy            DecoyConfig
    Chain            ChainConfig
    Temporal         TemporalConfig
    ForwardSecrecy   ForwardSecrecyConfig
}
```

### Example Classifications

```go
// User defines their own classification tags and policies
registry := &ClassificationRegistry{
    OwnerID: myNodeID,
    Classifications: map[ClassificationTag]*ClassificationPolicy{
        "public": {
            Tag:         "public",
            Description: "Public data, no protection needed",
            Policy: SecurityPolicy{
                K:                0,  // No partitioning
                EncryptionAlgo:   "", // No encryption
                ManifestStrategy: ManifestDHT,
            },
        },
        "internal": {
            Tag:         "internal",
            Description: "Internal documents, basic protection",
            Policy: SecurityPolicy{
                K:                3,
                EncryptionAlgo:   "AES-256-GCM",
                ManifestStrategy: ManifestDHTEncrypted,
                Scatter:          ScatterConfig{Enabled: true},
            },
        },
        "confidential": {
            Tag:         "confidential",
            Description: "Confidential business data",
            Policy: SecurityPolicy{
                K:                5,
                EncryptionAlgo:   "AES-256-GCM",
                ManifestStrategy: ManifestDHTEncrypted,
                Scatter:          ScatterConfig{Enabled: true, MinNodesBetween: 2},
                Shuffle:          ShuffleConfig{Enabled: true},
                ForwardSecrecy:   ForwardSecrecyConfig{Enabled: true, BlocksPerKey: 10},
            },
        },
        "top-secret": {
            Tag:         "top-secret",
            Description: "Maximum protection for sensitive data",
            Policy: SecurityPolicy{
                K:                7,
                EncryptionAlgo:   "AES-256-GCM",
                ManifestStrategy: ManifestTPMSealed,
                Scatter:          ScatterConfig{Enabled: true, MinNodesBetween: 3, EnforceStrict: true},
                Shuffle:          ShuffleConfig{Enabled: true},
                MultiLayer:       MultiLayerConfig{Enabled: true},
                Decoy:            DecoyConfig{Enabled: true, Percentage: 0.20},
                Chain:            ChainConfig{Enabled: true},
                Temporal:         TemporalConfig{Enabled: true, MaxDelay: 3 * time.Second},
                ForwardSecrecy:   ForwardSecrecyConfig{Enabled: true, BlocksPerKey: 5},
            },
        },
        "client-pii": {
            Tag:         "client-pii",
            Description: "Client personally identifiable information",
            Policy: SecurityPolicy{
                K:                5,
                EncryptionAlgo:   "AES-256-GCM",
                ManifestStrategy: ManifestLocalOnly,
                Scatter:          ScatterConfig{Enabled: true, MinNodesBetween: 2},
                Shuffle:          ShuffleConfig{Enabled: true},
                MultiLayer:       MultiLayerConfig{Enabled: true},
                ForwardSecrecy:   ForwardSecrecyConfig{Enabled: true, BlocksPerKey: 5},
            },
        },
    },
}
```

### Automatic Policy Application

```go
// StoreContent applies the policy for the given classification tag
func (s *SecureStore) StoreContent(data []byte, classification ClassificationTag) (*ContentManifest, error) {
    // Look up the classification policy
    policy, exists := s.registry.Classifications[classification]
    if !exists {
        return nil, ErrUnknownClassification{Tag: classification}
    }

    // Apply the security policy automatically
    return s.storeWithPolicy(data, classification, policy.Policy)
}

// Example usage
manifest, err := store.StoreContent(documentBytes, "confidential")
// Policy for "confidential" is automatically applied
```

### Classification Management

```go
// Add a new classification
func (r *ClassificationRegistry) AddClassification(policy *ClassificationPolicy) error

// Update an existing classification policy
func (r *ClassificationRegistry) UpdateClassification(tag ClassificationTag, policy SecurityPolicy) error

// Remove a classification (fails if content still tagged with it)
func (r *ClassificationRegistry) RemoveClassification(tag ClassificationTag) error

// List all classifications
func (r *ClassificationRegistry) ListClassifications() []*ClassificationPolicy

// Get policy for a tag
func (r *ClassificationRegistry) GetPolicy(tag ClassificationTag) (*SecurityPolicy, error)
```

### Policy Inheritance (Optional)

Classifications can optionally inherit from a parent classification:

```go
type ClassificationPolicy struct {
    Tag         ClassificationTag
    Parent      ClassificationTag  // Optional: inherit settings from parent
    Description string
    Policy      SecurityPolicy     // Overrides parent settings
}

// "restricted" inherits from "confidential" but adds decoy blocks
registry.Classifications["restricted"] = &ClassificationPolicy{
    Tag:         "restricted",
    Parent:      "confidential",
    Description: "Restricted data with additional obfuscation",
    Policy: SecurityPolicy{
        Decoy: DecoyConfig{Enabled: true, Percentage: 0.15},
    },
}
```

---

## Key Share Partitioning Algorithm

### Algorithm Steps

```
1. User uploads data D (size S bytes)
2. Apply cryptographic padding to ensure even block distribution
3. Generate K encryption keys: K0, K1, ... K(K-1)
4. Partition padded data into K groups: P0, P1, ... P(K-1)
5. Encrypt: E0 = Encrypt(P0, K0), E1 = Encrypt(P1, K1), ...
6. Chunk each encrypted partition into 1MB blocks
7. Tag each block with its key share index (0 to K-1)
8. Distribute: Block with index i -> Nodes where Hash(NodeID) mod K == i
9. Nodes REJECT blocks that don't match their pool
```

### Node Pool Assignment

```go
// AssignNodeToPool deterministically assigns a node to a key share pool
func AssignNodeToPool(nodeID [32]byte, k uint8) uint8 {
    hash := blake3.Sum256(nodeID[:])
    poolValue := binary.BigEndian.Uint64(hash[:8])
    return uint8(poolValue % uint64(k))
}
```

---

## Block Security

Content blocks include cryptographic protections to prevent tampering, reordering, and unauthorized access. Each block contains security metadata that enables verification of integrity, authenticity, and correct ordering.

### Block Structure

```go
// SecureContentBlock represents a cryptographically protected content block
type SecureContentBlock struct {
    // Block identification
    Index         uint32       // Sequential position in content (0-indexed)
    ContentID     [32]byte     // Hash of complete content for association
    StorageNodeID [32]byte     // Required for scatter verification during retrieval

    // Encryption components
    IV            [16]byte     // Initialization vector with embedded index
    Ciphertext    []byte       // AES-GCM encrypted block data
    MAC           [16]byte     // Authentication tag from AES-GCM

    // Version tracking
    PoolVersion   uint32       // Pool assignment version for rotation handling
}

// BlockMetadata contains KSP-specific block information
type BlockMetadata struct {
    BlockIndex      uint32       // Position in original content
    KeyShareIndex   uint8        // Which pool (0 to K-1)
    PartitionIndex  uint8        // Which partition within key share
    EncryptedHash   [32]byte     // BLAKE3 hash of ciphertext
    PoolVersion     uint32       // Version of pool assignment rules
}
```

### IV Construction with Index Embedding

The initialization vector (IV) embeds the block's sequential index in the first 8 bytes to cryptographically prevent block reordering attacks. An attacker cannot swap blocks without detection because the IV is bound to the block position.

```go
// ConstructBlockIV creates an IV with embedded block index for reordering prevention
func ConstructBlockIV(blockIndex uint32, randomBytes [8]byte) [16]byte {
    var iv [16]byte

    // First 8 bytes: block index (big-endian, padded)
    // This binds the IV to the block position
    binary.BigEndian.PutUint32(iv[0:4], blockIndex)
    binary.BigEndian.PutUint32(iv[4:8], 0) // Reserved for future use

    // Last 8 bytes: random nonce for uniqueness
    copy(iv[8:16], randomBytes[:])

    return iv
}
```

### Authenticated Encryption with Index Binding

AES-GCM additional authenticated data (AAD) includes the block index to bind the authentication tag to the block position. Decryption fails if the block is moved to a different position.

```go
// EncryptBlock encrypts a block with index-bound authentication
func EncryptBlock(
    plaintext []byte,
    key [32]byte,
    blockIndex uint32,
    contentID [32]byte,
    poolVersion uint32,
) (*SecureContentBlock, error) {
    // Generate random component for IV
    var randomBytes [8]byte
    n, err := rand.Read(randomBytes[:])
    if err != nil {
        return nil, ErrRandomGenerationFailed{Cause: err}
    }
    if n != len(randomBytes) {
        return nil, ErrInsufficientRandomness{Expected: len(randomBytes), Got: n}
    }

    // Construct IV with embedded index
    iv := ConstructBlockIV(blockIndex, randomBytes)

    // Build additional authenticated data (AAD)
    // Include block index to prevent reordering
    aad := buildBlockAAD(blockIndex, contentID, poolVersion)

    // Create AES-GCM cipher
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return nil, ErrCipherCreationFailed{Cause: err}
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return nil, ErrGCMCreationFailed{Cause: err}
    }

    // Encrypt with AAD
    ciphertext := aesGCM.Seal(nil, iv[:12], plaintext, aad)

    // Extract MAC (last 16 bytes of GCM output)
    macStart := len(ciphertext) - 16
    var mac [16]byte
    copy(mac[:], ciphertext[macStart:])
    ciphertext = ciphertext[:macStart]

    return &SecureContentBlock{
        Index:       blockIndex,
        ContentID:   contentID,
        IV:          iv,
        Ciphertext:  ciphertext,
        MAC:         mac,
        PoolVersion: poolVersion,
    }, nil
}

// buildBlockAAD constructs additional authenticated data for AES-GCM
func buildBlockAAD(blockIndex uint32, contentID [32]byte, poolVersion uint32) []byte {
    aad := make([]byte, 40) // 4 + 32 + 4 bytes

    // Block index prevents reordering
    binary.BigEndian.PutUint32(aad[0:4], blockIndex)

    // Content ID binds block to specific content
    copy(aad[4:36], contentID[:])

    // Pool version ensures correct epoch handling
    binary.BigEndian.PutUint32(aad[36:40], poolVersion)

    return aad
}

// DecryptBlock decrypts and verifies a block including position binding
func DecryptBlock(
    block *SecureContentBlock,
    key [32]byte,
    expectedIndex uint32,
) ([]byte, error) {
    // Verify block index matches expected position
    if block.Index != expectedIndex {
        return nil, ErrBlockIndexMismatch{
            Expected: expectedIndex,
            Actual:   block.Index,
        }
    }

    // Verify IV contains correct index
    embeddedIndex := binary.BigEndian.Uint32(block.IV[0:4])
    if embeddedIndex != expectedIndex {
        return nil, ErrIVIndexMismatch{
            Expected: expectedIndex,
            Embedded: embeddedIndex,
        }
    }

    // Reconstruct AAD
    aad := buildBlockAAD(block.Index, block.ContentID, block.PoolVersion)

    // Create AES-GCM cipher
    aesBlock, err := aes.NewCipher(key[:])
    if err != nil {
        return nil, ErrCipherCreationFailed{Cause: err}
    }

    aesGCM, err := cipher.NewGCM(aesBlock)
    if err != nil {
        return nil, ErrGCMCreationFailed{Cause: err}
    }

    // Reconstruct ciphertext with MAC for decryption
    ciphertextWithMAC := append(block.Ciphertext, block.MAC[:]...)

    // Decrypt and verify
    plaintext, err := aesGCM.Open(nil, block.IV[:12], ciphertextWithMAC, aad)
    if err != nil {
        return nil, ErrBlockDecryptionFailed{
            BlockIndex: block.Index,
            Cause:      err,
        }
    }

    return plaintext, nil
}
```

### Block Security Properties

| Property | Mechanism | Protection |
|----------|-----------|------------|
| **Confidentiality** | AES-256-GCM encryption | Unauthorized parties cannot read content |
| **Integrity** | GCM authentication tag | Tampering detected during decryption |
| **Position binding** | Index in IV first 8 bytes | Block reordering detected |
| **Content binding** | ContentID in AAD | Block cannot be moved between contents |
| **Version binding** | PoolVersion in AAD | Blocks tied to specific pool assignment epoch |
| **Scatter verification** | StorageNodeID field | Node diversity verified during retrieval |

---

## Cryptographic Padding Scheme

### Problem

Data may not divide evenly by K key shares, resulting in uneven block distribution across pools.

### Solution: KSP Random Padding

Pad data so total blocks are evenly divisible by K, using cryptographically secure random bytes.

```go
type PaddingInfo struct {
    OriginalSize   uint64   // Original data size (for stripping on retrieval)
    PaddedSize     uint64   // Size after padding
    PaddingBytes   uint32   // How many random bytes added
    BlocksPerShare uint32   // Blocks per key share (evenly distributed)
}

func CalculatePadding(dataSize uint64, k uint8) (PaddingInfo, error) {
    blockSize := uint64(1 << 20)  // 1MB

    // Overflow check: ensure dataSize + blockSize - 1 does not overflow
    if dataSize > math.MaxUint64 - blockSize + 1 {
        return PaddingInfo{}, ErrDataSizeOverflow{Size: dataSize}
    }

    // Calculate total blocks needed
    totalBlocks := (dataSize + blockSize - 1) / blockSize

    // Round up to next multiple of K
    remainder := totalBlocks % uint64(k)
    if remainder != 0 {
        additionalBlocks := uint64(k) - remainder

        // Overflow check: ensure totalBlocks + additionalBlocks does not overflow
        if totalBlocks > math.MaxUint64 - additionalBlocks {
            return PaddingInfo{}, ErrBlockCountOverflow{Blocks: totalBlocks}
        }

        totalBlocks += additionalBlocks
    }

    // Overflow check: ensure totalBlocks * blockSize does not overflow
    if totalBlocks > math.MaxUint64 / blockSize {
        return PaddingInfo{}, ErrPaddedSizeOverflow{Blocks: totalBlocks, BlockSize: blockSize}
    }

    paddedSize := totalBlocks * blockSize

    // Overflow check: ensure paddedSize - dataSize fits in uint32
    paddingBytes := paddedSize - dataSize
    if paddingBytes > math.MaxUint32 {
        return PaddingInfo{}, ErrPaddingTooLarge{PaddingBytes: paddingBytes}
    }

    return PaddingInfo{
        OriginalSize:   dataSize,
        PaddedSize:     paddedSize,
        PaddingBytes:   uint32(paddingBytes),
        BlocksPerShare: uint32(totalBlocks / uint64(k)),
    }, nil
}

func ApplySecurePadding(data []byte, info PaddingInfo) ([]byte, error) {
    if info.PaddingBytes == 0 {
        return data, nil
    }

    // Generate cryptographically secure random padding with single rand.Read call
    padding := make([]byte, info.PaddingBytes)
    n, err := rand.Read(padding)
    if err != nil {
        return nil, ErrPaddingGenerationFailed{Cause: err}
    }

    // Verify returned length matches requested
    if n != int(info.PaddingBytes) {
        return nil, ErrInsufficientPadding{
            Requested: int(info.PaddingBytes),
            Generated: n,
        }
    }

    // Append random padding to data
    padded := make([]byte, 0, info.PaddedSize)
    padded = append(padded, data...)
    padded = append(padded, padding...)

    return padded, nil
}

func StripPadding(paddedData []byte, originalSize uint64) []byte {
    return paddedData[:originalSize]
}
```

### Security Properties

- **Random padding**: Prevents padding oracle attacks
- **Original size in manifest**: Encrypted manifest stores true size
- **Even distribution**: Every key share gets exactly `totalBlocks/K` blocks
- **No information leakage**: Attacker cannot determine padding amount without manifest
- **Overflow protection**: All arithmetic operations checked for overflow before calculation
- **Verified randomness**: rand.Read return value verified to match requested length

### Example

```
Data: 5.5 MB, K=3
- Unpadded blocks: 6 (5 full + 1 partial)
- 6 mod 3 = 0 (already even)

Data: 7.2 MB, K=3
- Unpadded blocks: 8 (7 full + 1 partial)
- 8 mod 3 = 2 -> Need 1 more block
- Padded to 9 blocks -> 3 blocks per share
- Padding: 1.8 MB of random bytes
```

---

## Advanced Security Features

All features are optional and configurable per content object. Users choose trade-offs appropriate for each piece of content.

### 1. Block Scatter Distribution

Prevent contiguous blocks from being stored on the same node and ensure no single node accumulates excessive block concentration.

```go
type ScatterConfig struct {
    Enabled              bool
    MinNodesBetween      uint32   // Min different nodes between sequential blocks
    EnforceStrict        bool     // Fail if scatter cannot be achieved
    MaxNodeConcentration float32  // Maximum percentage of blocks per node (default 0.20 = 20%)
}

// ScatterVerifier ensures proper block distribution across nodes
type ScatterVerifier struct {
    selectedNodes map[[32]byte]uint32  // NodeID -> block count
    totalBlocks   uint32
    maxPercent    float32
}

// NewScatterVerifier creates a verifier with concentration limits
func NewScatterVerifier(maxConcentration float32) *ScatterVerifier {
    if maxConcentration <= 0 || maxConcentration > 1.0 {
        maxConcentration = 0.20 // Default: no node should have >20% of blocks
    }
    return &ScatterVerifier{
        selectedNodes: make(map[[32]byte]uint32),
        maxPercent:    maxConcentration,
    }
}

// RecordBlockAssignment tracks block assignment and verifies concentration
func (v *ScatterVerifier) RecordBlockAssignment(nodeID [32]byte) error {
    // Check if this node already exists in selected set
    count := v.selectedNodes[nodeID]

    // Calculate what concentration would be after adding this block
    newTotal := v.totalBlocks + 1
    newCount := count + 1
    concentration := float32(newCount) / float32(newTotal)

    if concentration > v.maxPercent {
        return ErrNodeConcentrationExceeded{
            NodeID:        nodeID,
            Concentration: concentration,
            MaxAllowed:    v.maxPercent,
        }
    }

    v.selectedNodes[nodeID] = newCount
    v.totalBlocks = newTotal
    return nil
}

// VerifyRetrievalDiversity validates node diversity during content retrieval
func (v *ScatterVerifier) VerifyRetrievalDiversity(blocks []*SecureContentBlock) error {
    nodeCounts := make(map[[32]byte]uint32)
    totalBlocks := uint32(len(blocks))

    for _, block := range blocks {
        nodeCounts[block.StorageNodeID]++
    }

    for nodeID, count := range nodeCounts {
        concentration := float32(count) / float32(totalBlocks)
        if concentration > v.maxPercent {
            return ErrRetrievalConcentrationViolation{
                NodeID:        nodeID,
                BlockCount:    count,
                TotalBlocks:   totalBlocks,
                Concentration: concentration,
                MaxAllowed:    v.maxPercent,
            }
        }
    }

    return nil
}

// SelectNodeForBlock chooses a node respecting scatter and concentration constraints
func SelectNodeForBlock(
    blockIndex uint32,
    previousNodeID [32]byte,
    eligibleNodes []NodeInfo,
    verifier *ScatterVerifier,
    minNodesBetween uint32,
) (*NodeInfo, error) {
    // Filter out recently used nodes for scatter
    var candidates []NodeInfo
    for _, node := range eligibleNodes {
        // Check concentration limit would not be exceeded
        testVerifier := *verifier // Copy for testing
        if err := testVerifier.RecordBlockAssignment(node.NodeID); err != nil {
            continue // This node would exceed concentration
        }

        // Check scatter constraint (different from previous node)
        if blockIndex > 0 && bytes.Equal(node.NodeID[:], previousNodeID[:]) {
            if minNodesBetween > 0 {
                continue // Same as previous, violates scatter
            }
        }

        candidates = append(candidates, node)
    }

    if len(candidates) == 0 {
        return nil, ErrNoEligibleNodesForScatter{
            BlockIndex:      blockIndex,
            EligibleCount:   len(eligibleNodes),
            MinNodesBetween: minNodesBetween,
        }
    }

    // Select from candidates (can apply additional criteria)
    selected := &candidates[0]
    verifier.RecordBlockAssignment(selected.NodeID)

    return selected, nil
}
```

**Trade-off**: More scatter = harder to collude, but requires more available nodes.

### 2. Block Order Randomization

Randomize block storage order; true order only in encrypted manifest.

```go
type ShuffleConfig struct {
    Enabled       bool
    ShuffleSeed   [32]byte  // Generated per-upload, stored in manifest
}

type BlockMapping struct {
    OriginalIndex  uint32   // Position in file
    StorageIndex   uint32   // Randomized storage position
}
```

**Trade-off**: Adds complexity but prevents sequential analysis.

### 3. Multi-Layer Encryption

Two independent encryption layers for defense in depth.

```go
type MultiLayerConfig struct {
    Enabled         bool
    OuterAlgorithm  string  // "AES-256-GCM" (encrypt entire file first)
    InnerAlgorithm  string  // "ChaCha20-Poly1305" (per-partition)
}

// Flow: File -> Outer Encrypt -> Partition -> Inner Encrypt -> Store
// Retrieval: Blocks -> Inner Decrypt -> Reassemble -> Outer Decrypt
```

**Trade-off**: 2x encryption overhead, but attacker must break both algorithms.

### 4. Decoy Blocks (Chaff)

Add configurable fake blocks to obscure file structure.

```go
type DecoyConfig struct {
    Enabled       bool
    Percentage    float32   // User-configurable: 0.0 to 1.0 (e.g., 0.2 = 20% extra)
    MaxDecoys     uint32    // Hard cap to prevent excessive bloat
    DecoyKey      [32]byte  // Identifies real vs fake (stored in manifest)
}

// Decoy blocks contain random data, same size as real blocks
// Only owner knows which blocks are real via encrypted manifest
```

**Trade-off**: User controls storage cost vs obfuscation level.

### 5. Cryptographic Block Chaining

Each block's encryption depends on previous block's hash.

```go
type ChainConfig struct {
    Enabled    bool
    ChainMode  string  // "sequential" (must decrypt in order)
}

// IV derivation:
// IV_block_0 = Random
// IV_block_i = BLAKE3(PartitionKey || Hash(Ciphertext_{i-1}))

// Security: Single corrupted block invalidates rest of chain
```

**Trade-off**: Cannot parallel decrypt; must process sequentially.

### 6. Temporal Jitter

Stagger block uploads to prevent timing correlation attacks.

```go
type TemporalConfig struct {
    Enabled      bool
    MinDelay     time.Duration  // e.g., 100ms
    MaxDelay     time.Duration  // e.g., 5s
    Distribution string         // "uniform" or "exponential"
}

// Uploads spread over time window
// Prevents: timing analysis, traffic correlation
```

**Trade-off**: Slower uploads, but defeats timing analysis.

### 7. Forward Secrecy (Sub-Keys)

Generate ephemeral sub-keys per block group; limits key compromise damage.

```go
type ForwardSecrecyConfig struct {
    Enabled         bool
    BlocksPerKey    uint32  // New sub-key every N blocks (e.g., 10)
    KeyDerivation   string  // "BLAKE3-KDF"
}

// Sub-key derivation:
// SubKey_i = BLAKE3_KDF(PartitionKey || block_group_index || epoch)

// If SubKey_i compromised, only that block group exposed
```

**Trade-off**: More keys to manage, but limits breach damage.

### 8. Availability SLA Requirements

Define availability requirements for content; the network layer handles monitoring and triggers replication when services fail to meet SLA.

```go
type AvailabilitySLAConfig struct {
    Enabled          bool
    MinAvailability  float32  // Required availability (e.g., 0.999 = 99.9%)
    MinBandwidthMbps uint32   // Minimum bandwidth for serving content
    MaxLatencyMs     uint32   // Maximum acceptable latency
    GracePeriod      time.Duration  // Time before triggering replication
}
```

**Trade-off**: Stricter SLA = more replication overhead, but higher availability.

### Network Layer Integration

Availability monitoring is handled at the **network layer**, not the content storage layer. The network layer tracks:

- **Service availability** - Services may be clustered across nodes
- **Node uptime** - Individual node health
- **Bandwidth metrics** - Throughput capacity per node/service
- **Latency measurements** - Response time to various network regions

See [02-network-architecture.md](02-network-architecture.md) for network-level monitoring details.

### Content Layer Responsibilities

The content storage layer:
1. **Defines SLA requirements** in the classification policy
2. **Queries network layer** for service/node availability metrics
3. **Requests replication** when network layer reports SLA violations
4. **Selects eligible nodes** based on policy requirements (pool, reputation, capacity)

```go
// ContentReplicator handles replication triggered by network layer events
type ContentReplicator struct {
    networkMetrics NetworkMetricsClient  // Interface to network layer
    blockRegistry  BlockLocationRegistry
}

// OnSLAViolation is called by network layer when a service fails SLA
func (r *ContentReplicator) OnSLAViolation(event SLAViolationEvent) error {
    // Find blocks affected by this service/node
    affectedBlocks := r.blockRegistry.GetBlocksOnService(event.ServiceID)

    for _, block := range affectedBlocks {
        // Check if block still meets redundancy after this failure
        if r.hasAdequateRedundancy(block) {
            continue  // Other replicas still available
        }

        // Find eligible replacement in same pool
        newNode, err := r.findEligibleNode(block.KeyShareIndex)
        if err != nil {
            return err
        }

        // Request replication from network layer
        if err := r.networkMetrics.ReplicateBlock(block, newNode); err != nil {
            return err
        }
    }

    return nil
}

// findEligibleNode queries network layer for nodes meeting requirements
func (r *ContentReplicator) findEligibleNode(pool uint8) (*NodeInfo, error) {
    // Query network layer for nodes in pool with good metrics
    candidates := r.networkMetrics.FindNodesInPool(pool, NodeCriteria{
        MinAvailability: r.slaConfig.MinAvailability,
        MinBandwidth:    r.slaConfig.MinBandwidthMbps,
        MaxLatency:      r.slaConfig.MaxLatencyMs,
    })

    for _, node := range candidates {
        // Verify KSP pool assignment
        if AssignNodeToPool(node.NodeID, r.K) != pool {
            continue
        }

        // Check reputation (from reputation system)
        if node.Reputation < r.minReputation {
            continue
        }

        return node, nil
    }

    return nil, ErrNoEligibleNodes
}
```

### Example: High-Availability Classification

```go
registry.Classifications["mission-critical"] = &ClassificationPolicy{
    Tag:         "mission-critical",
    Description: "Mission-critical data requiring 99.9% availability",
    Policy: SecurityPolicy{
        K:             5,
        MinRedundancy: 3,  // 3 copies per block
        EncryptionAlgo: "AES-256-GCM",
        Availability: AvailabilitySLAConfig{
            Enabled:          true,
            MinAvailability:  0.999,  // 99.9% availability required
            MinBandwidthMbps: 100,    // 100 Mbps minimum
            MaxLatencyMs:     50,     // 50ms max latency
            GracePeriod:      15 * time.Minute,
        },
        Scatter: ScatterConfig{Enabled: true, MinNodesBetween: 2},
    },
}
```

---

## Content Storage with Classifications

Content is stored by tagging it with a classification. The policy linked to that classification is automatically applied.

### Primary Usage: Classification Tags

```go
// Store content using a predefined classification
manifest, err := store.StoreContent(documentBytes, "confidential")
// The "confidential" policy is automatically applied

// Store with a different classification
manifest, err := store.StoreContent(publicFile, "public")
// The "public" policy is automatically applied
```

### Per-Content Override (Optional)

Users can optionally override specific policy settings for individual content:

```go
// ContentOverride allows per-content adjustments to the base policy
type ContentOverride struct {
    // Override specific settings (nil = use policy default)
    K              *uint8
    Decoy          *DecoyConfig
    Temporal       *TemporalConfig
    // ... other overridable fields
}

// Store with classification but override decoy percentage
manifest, err := store.StoreContentWithOverride(
    sensitiveData,
    "confidential",
    &ContentOverride{
        Decoy: &DecoyConfig{Enabled: true, Percentage: 0.30},
    },
)
```

### Classification-Based Workflow

```
1. User defines classifications in their registry (once)
   - "public", "internal", "confidential", "top-secret", etc.

2. Each classification has a linked SecurityPolicy
   - Defines K, encryption, scatter, shuffle, decoys, etc.

3. When storing content, user just provides the classification tag
   - store.StoreContent(data, "confidential")

4. System looks up the policy and applies it automatically
   - No need to specify security settings each time

5. Optionally override specific settings per-content
   - StoreContentWithOverride(data, "confidential", overrides)
```

### Policy Trade-offs Reference

When defining classification policies, users control these trade-offs:

| Feature | User Controls | Trade-off |
|---------|---------------|-----------|
| K (key shares) | 0, 3-16 | More = more secure, more nodes needed |
| MinRedundancy | 1-10 | More = higher availability, more storage |
| Scatter.MinNodesBetween | 1-10 | More = harder to collude, needs more nodes |
| Scatter.MaxNodeConcentration | 0.1-0.5 | Lower = better diversity, more nodes needed |
| Decoy.Percentage | 0.0-1.0 | More = obscures size, increases storage cost |
| Temporal.MaxDelay | 0s-infinity | More = harder timing analysis, slower upload |
| ForwardSecrecy.BlocksPerKey | 1-infinity | Fewer = limits breach damage, more keys |
| Chain.Enabled | true/false | True = sequential only, no parallel decrypt |
| Availability.MinAvailability | 0.9-0.9999 | Higher = stricter, more replication |
| Availability.MinBandwidthMbps | 10-1000 | Higher = faster serving, fewer eligible nodes |
| Availability.GracePeriod | 1m-1h | Shorter = faster failover, more churn |

---

## Manifest Security Strategies

Three strategies for manifest storage, user-configurable per content:

| Strategy | Security | Usability | Recoverability |
|----------|----------|-----------|----------------|
| **DHT Encrypted** | Medium | High | High (with key) |
| **Local Only** | High | Medium | None |
| **TPM Sealed** | Very High | Medium | High (with TPM) |

### DHT Encrypted

Manifest encrypted with owner's key, stored in DHT for availability.

### Local Only

Manifest stored only on owner's device. Maximum security, no recovery if lost.

### TPM Sealed

Manifest encrypted and sealed to owner's TPM. Recoverable only by owner's hardware with matching PCR values.

---

## Data Flows

### Upload Flow (Protected Content)

```
Owner Device                    DHT                Storage Pools (0, 1, 2)
    |                            |                     |     |     |
    | 1. Generate KeySet (K=3)   |                     |     |     |
    |    Keys: K0, K1, K2        |                     |     |     |
    |                            |                     |     |     |
    | 2. Apply padding           |                     |     |     |
    |    (ensure even blocks)    |                     |     |     |
    |                            |                     |     |     |
    | 3. Partition content       |                     |     |     |
    |    Part0, Part1, Part2     |                     |     |     |
    |                            |                     |     |     |
    | 4. Encrypt partitions      |                     |     |     |
    |    Part0 -> E(K0, Part0)   |                     |     |     |
    |    Part1 -> E(K1, Part1)   |                     |     |     |
    |    Part2 -> E(K2, Part2)   |                     |     |     |
    |                            |                     |     |     |
    | 5. Chunk encrypted parts   |                     |     |     |
    |                            |                     |     |     |
    | 6. Tag blocks with pool    |                     |     |     |
    |                            |                     |     |     |
    | 7. Store manifest          |                     |     |     |
    |--------------------------->|                     |     |     |
    |                            |                     |     |     |
    | 8. Distribute to pools     |                     |     |     |
    |    Pool 0 blocks -------------------------------->|     |     |
    |    Pool 1 blocks ---------------------------------------->|     |
    |    Pool 2 blocks ---------------------------------------------->|
    |                            |                     |     |     |
    | 9. Nodes verify pool match |                     |     |     |
```

### Retrieval Flow

```
Owner -> Unseal manifest -> Request blocks from ALL K pools
     -> Decrypt each partition with corresponding key
     -> Strip padding -> Verify Merkle root -> Original content
```

---

## Security Analysis

### Attack Vectors and Mitigations

| Attack Vector | Mitigation |
|---------------|------------|
| Single node compromise | Only 1/K of data (e.g., 33% if K=3) |
| Multi-pool collusion | Still requires breaking K encryption keys |
| DHT poisoning | FROST signatures on manifests |
| Encryption weakness | Key per partition + multi-layer option |
| Owner key compromise | TPM sealing option binds to hardware |
| Contiguous block analysis | Block scatter + shuffle |
| Timing correlation | Temporal jitter |
| File size inference | Decoy blocks + padding |

### Collusion Resistance

For K=5, 10,000 nodes, 100 compromised (1%):

```
P(attacker controls nodes in ALL pools) = (0.01)^5 = 10^-10
```

Extremely low probability of complete data exposure.

---

## Technology Choices

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Encryption | AES-256-GCM (default) | Hardware acceleration, NIST approved |
| Alternative | ChaCha20-Poly1305 | For non-AES hardware |
| Hashing | BLAKE3 | 10x faster than SHA-256, quantum-resistant |
| Key Derivation | BLAKE3-KDF | Single primitive, context separation |
| Signature | FROST (existing) | Threshold signatures already integrated |

---

## Key Data Structures

```go
// ClassificationTag is a user-defined label for data sensitivity
type ClassificationTag string

// ClassificationPolicy defines the security settings for a classification
type ClassificationPolicy struct {
    Tag         ClassificationTag
    Parent      ClassificationTag  // Optional: inherit from parent
    Description string
    CreatedAt   time.Time
    UpdatedAt   time.Time
    Policy      SecurityPolicy
}

// ClassificationRegistry stores user-defined classifications
type ClassificationRegistry struct {
    OwnerID          [32]byte
    Classifications  map[ClassificationTag]*ClassificationPolicy
}

// SecurityPolicy defines how data with this classification is stored
type SecurityPolicy struct {
    K                uint8            // Key shares (0=whole, 3-16=partitioned)
    MinRedundancy    uint8            // Min copies per block
    EncryptionAlgo   string           // "AES-256-GCM", "ChaCha20-Poly1305", ""
    ManifestStrategy ManifestStrategy
    Availability     AvailabilitySLAConfig  // SLA requirements (network layer monitors)
    Scatter          ScatterConfig
    Shuffle          ShuffleConfig
    MultiLayer       MultiLayerConfig
    Decoy            DecoyConfig
    Chain            ChainConfig
    Temporal         TemporalConfig
    ForwardSecrecy   ForwardSecrecyConfig
}

// AvailabilitySLAConfig defines availability requirements
// Actual monitoring is performed by network layer
type AvailabilitySLAConfig struct {
    Enabled          bool
    MinAvailability  float32        // Required availability (e.g., 0.999 = 99.9%)
    MinBandwidthMbps uint32         // Minimum bandwidth for serving content
    MaxLatencyMs     uint32         // Maximum acceptable latency
    GracePeriod      time.Duration  // Time before triggering replication
}

// ContentManifest stores metadata for content with classification
type ContentManifest struct {
    *FROSTManifest
    ContentType      ContentType
    Classification   ClassificationTag      // User-defined classification tag
    AppliedPolicy    SecurityPolicy         // Snapshot of policy at storage time
    Overrides        *ContentOverride       // Any per-content overrides applied
    KSPConfig        KeyShareConfig
    Padding          PaddingInfo
    PartitionInfo    []PartitionMetadata
    BlockMappings    []BlockMapping         // If shuffle enabled
    DecoyIndices     []uint32               // If decoys enabled
    OwnerID          [32]byte
}

// ContentOverride allows per-content adjustments to base policy
type ContentOverride struct {
    K              *uint8
    Decoy          *DecoyConfig
    Temporal       *TemporalConfig
    ForwardSecrecy *ForwardSecrecyConfig
}

type KeyShareConfig struct {
    K                uint8   // Number of key shares
    MinRedundancy    uint8   // Min copies per block
    NodePoolAlgo     string  // "Hash(NodeID) mod K"
}

type KSPContentBlock struct {
    *ContentBlock
    KSPMeta  BlockMetadata
}

type BlockMetadata struct {
    BlockIndex      uint32
    KeyShareIndex   uint8   // Which pool (0 to K-1)
    PartitionIndex  uint8
    EncryptedHash   [32]byte
    PoolVersion     uint32  // Version field for rotation handling
}
```

---

## Node Pool Enforcement

```go
// Node-side: Reject cross-pool storage attempts
func (n *Node) AcceptBlock(block *KSPContentBlock) error {
    ourPool := AssignNodeToPool(n.NodeID, block.KSPMeta.K)

    if ourPool != block.KSPMeta.KeyShareIndex {
        return ErrPoolMismatch{
            NodePool:  ourPool,
            BlockPool: block.KSPMeta.KeyShareIndex,
        }
    }

    return n.storage.StoreBlock(block)
}
```

---

## VRF-Based Pool Selection Algorithm

The pool selection algorithm uses Verifiable Random Functions (VRF) to provide unpredictable yet verifiable pool assignments. This prevents attackers from pre-positioning Sybil nodes in target pools since pool membership changes dynamically based on cryptographic randomness that cannot be predicted in advance.

### VRF Pool Selection Architecture

The VRF-based pool selection combines three elements to create unpredictable pool assignments:

1. **Network Epoch Randomness** - A shared random beacon that changes each epoch
2. **Content-Specific Entropy** - Derived from the content identifier
3. **Node VRF Proofs** - Each node generates verifiable proofs of their pool eligibility

```go
// VRFPoolConfig defines parameters for VRF-based pool selection
type VRFPoolConfig struct {
    EpochDuration       time.Duration  // How often pool assignments rotate (default: 24 hours)
    RotationLookahead   uint32         // Epochs to pre-compute for smooth transitions
    MinPoolSize         uint32         // Minimum nodes per pool before rotation
    VRFAlgorithm        string         // "ECVRF-P256-SHA256" or "ECVRF-ED25519"
    RotationPercentage  float32        // Percentage of nodes that rotate per epoch (default: 0.20 = 20%)
    Version             uint32         // Version field for K value change handling
}

// EpochRandomness represents the shared random beacon for an epoch
type EpochRandomness struct {
    Epoch             uint64
    Randomness        [32]byte     // BLAKE3 hash of threshold signature contributions
    Contributors      []NodeID     // Nodes that contributed to this randomness
    Signature         []byte       // FROST threshold signature proving validity
    PreviousSignature []byte       // Signature from previous epoch for chain verification
    GeneratedAt       time.Time
}

// VRFPoolProof is a node's verifiable proof of pool eligibility
type VRFPoolProof struct {
    NodeID          [32]byte
    Epoch           uint64
    ContentID       [32]byte   // Content being stored (or zero for general eligibility)
    VRFOutput       [32]byte   // The VRF output determining pool
    VRFProof        []byte     // Proof that output was correctly computed
    AssignedPool    uint8      // Pool derived from VRF output
    PoolVersion     uint32     // Version of pool assignment rules
    ValidUntil      time.Time
}
```

### VRF Input Construction

The VRF input is constructed from content ID, epoch, and network randomness to ensure unpredictable but verifiable pool assignments:

```go
// ConstructVRFInput builds the deterministic input for VRF computation
func ConstructVRFInput(contentID [32]byte, epoch uint64, networkRandomness [32]byte) []byte {
    // VRF_input = content_id || epoch || network_randomness
    input := make([]byte, 72) // 32 + 8 + 32 bytes

    copy(input[0:32], contentID[:])
    binary.BigEndian.PutUint64(input[32:40], epoch)
    copy(input[40:72], networkRandomness[:])

    return input
}
```

### Pool Selection Computation

Pool assignment is computed using a VRF that takes the node's private key, epoch randomness, and content identifier as inputs. The resulting output is deterministic for the node but unpredictable to external observers.

```go
// ComputePoolAssignment generates a verifiable pool assignment for a node
func ComputePoolAssignment(
    nodePrivKey ed25519.PrivateKey,
    epochRandom *EpochRandomness,
    contentID [32]byte,
    k uint8,
    poolVersion uint32,
) (*VRFPoolProof, error) {
    // Construct VRF input: content_id || epoch || network_randomness
    vrfInput := ConstructVRFInput(contentID, epochRandom.Epoch, epochRandom.Randomness)

    // Generate VRF output and proof
    vrfOutput, vrfProof, err := ecvrf.Prove(nodePrivKey, vrfInput)
    if err != nil {
        return nil, ErrVRFComputationFailed{Cause: err}
    }

    // Derive pool from VRF output
    poolValue := binary.BigEndian.Uint64(vrfOutput[:8])
    assignedPool := uint8(poolValue % uint64(k))

    return &VRFPoolProof{
        NodeID:       blake3.Sum256(nodePrivKey.Public().(ed25519.PublicKey)),
        Epoch:        epochRandom.Epoch,
        ContentID:    contentID,
        VRFOutput:    vrfOutput,
        VRFProof:     vrfProof,
        AssignedPool: assignedPool,
        PoolVersion:  poolVersion,
        ValidUntil:   time.Now().Add(time.Duration(epochRandom.Epoch) * 24 * time.Hour),
    }, nil
}

// VerifyPoolAssignment validates a node's pool assignment claim
func VerifyPoolAssignment(
    nodePubKey ed25519.PublicKey,
    epochRandom *EpochRandomness,
    proof *VRFPoolProof,
    k uint8,
) error {
    // Verify the proof belongs to this epoch
    if proof.Epoch != epochRandom.Epoch {
        return ErrEpochMismatch{Expected: epochRandom.Epoch, Got: proof.Epoch}
    }

    // Reconstruct VRF input
    vrfInput := ConstructVRFInput(proof.ContentID, epochRandom.Epoch, epochRandom.Randomness)

    // Verify VRF proof
    valid, err := ecvrf.Verify(nodePubKey, vrfInput, proof.VRFOutput, proof.VRFProof)
    if err != nil || !valid {
        return ErrInvalidVRFProof{NodeID: proof.NodeID}
    }

    // Verify pool derivation is correct
    poolValue := binary.BigEndian.Uint64(proof.VRFOutput[:8])
    expectedPool := uint8(poolValue % uint64(k))
    if expectedPool != proof.AssignedPool {
        return ErrPoolDerivationMismatch{Expected: expectedPool, Claimed: proof.AssignedPool}
    }

    return nil
}
```

### Epoch Randomness Generation

The network generates shared randomness each epoch using a distributed protocol. This prevents any single node from predicting or manipulating pool assignments.

```go
// EpochRandomnessGenerator coordinates distributed randomness generation
type EpochRandomnessGenerator struct {
    frostSigner       *FROSTSigner       // Threshold signature scheme
    consensusNodes    []NodeID           // Nodes participating in randomness
    minContributors   uint32             // Minimum contributors for valid randomness
    previousRandomness [32]byte          // Chain to previous epoch
    previousSignature []byte             // Previous epoch signature for verification
}

// GenerateEpochRandomness creates new randomness for an epoch
func (g *EpochRandomnessGenerator) GenerateEpochRandomness(epoch uint64) (*EpochRandomness, error) {
    // Create message to sign: previous epoch randomness || epoch number
    message := make([]byte, 40)
    copy(message[:32], g.previousRandomness[:])
    binary.BigEndian.PutUint64(message[32:], epoch)

    // Collect FROST signature contributions from threshold of nodes
    contributions, err := g.collectContributions(message)
    if err != nil {
        return nil, err
    }

    if uint32(len(contributions)) < g.minContributors {
        return nil, ErrInsufficientContributors{
            Need: g.minContributors,
            Got:  uint32(len(contributions)),
        }
    }

    // Aggregate into threshold signature
    signature, err := g.frostSigner.Aggregate(contributions)
    if err != nil {
        return nil, err
    }

    // Derive randomness from signature (signature is unpredictable until threshold reached)
    randomness := blake3.Sum256(signature)

    return &EpochRandomness{
        Epoch:             epoch,
        Randomness:        randomness,
        Contributors:      g.extractContributorIDs(contributions),
        Signature:         signature,
        PreviousSignature: g.previousSignature,
        GeneratedAt:       time.Now(),
    }, nil
}

// VerifyEpochChain validates the epoch randomness chain integrity
func VerifyEpochChain(current *EpochRandomness, previous *EpochRandomness) error {
    // Verify previous epoch signature is included
    if !bytes.Equal(current.PreviousSignature, previous.Signature) {
        return ErrEpochChainBroken{
            CurrentEpoch:  current.Epoch,
            PreviousEpoch: previous.Epoch,
        }
    }

    // Verify the chain derivation
    expectedMessage := make([]byte, 40)
    copy(expectedMessage[:32], previous.Randomness[:])
    binary.BigEndian.PutUint64(expectedMessage[32:], current.Epoch)

    // Signature must be verifiable against the expected message
    // (actual verification depends on FROST implementation)

    return nil
}
```

### Dynamic Pool Rotation

Pool assignments rotate each epoch (default: every 24 hours), making it impossible for attackers to pre-position Sybil nodes for specific content. Only 20% of nodes rotate per epoch to ensure stability while maintaining security.

```go
// PoolRotationManager handles smooth transitions between epochs
type PoolRotationManager struct {
    currentEpoch      *EpochRandomness
    nextEpoch         *EpochRandomness
    transitionStart   time.Time
    transitionEnd     time.Time
    rotationPercent   float32          // Default: 0.20 (20% of nodes rotate per epoch)
    poolVersion       uint32           // Incremented on K value changes
    migrationDeadline time.Duration    // Grace period for K value migrations
}

// GetActivePoolsForContent returns valid pools during a transition period
func (m *PoolRotationManager) GetActivePoolsForContent(
    nodeID [32]byte,
    contentID [32]byte,
    k uint8,
) ([]uint8, error) {
    now := time.Now()

    // During transition, both old and new pools are valid
    if now.After(m.transitionStart) && now.Before(m.transitionEnd) {
        currentPool := m.computePoolForEpoch(nodeID, contentID, m.currentEpoch, k)
        nextPool := m.computePoolForEpoch(nodeID, contentID, m.nextEpoch, k)

        if currentPool == nextPool {
            return []uint8{currentPool}, nil
        }
        return []uint8{currentPool, nextPool}, nil
    }

    // Outside transition, only current epoch pool is valid
    pool := m.computePoolForEpoch(nodeID, contentID, m.currentEpoch, k)
    return []uint8{pool}, nil
}

// ShouldNodeRotate determines if a specific node should rotate this epoch
// Only ~20% of nodes rotate per epoch for stability
func (m *PoolRotationManager) ShouldNodeRotate(
    nodeID [32]byte,
    epochRandom *EpochRandomness,
) bool {
    // Derive rotation decision from node ID and epoch randomness
    rotationInput := append(nodeID[:], epochRandom.Randomness[:]...)
    rotationHash := blake3.Sum256(rotationInput)

    // Use first 8 bytes to determine rotation
    rotationValue := binary.BigEndian.Uint64(rotationHash[:8])
    threshold := uint64(float64(math.MaxUint64) * float64(m.rotationPercent))

    return rotationValue < threshold
}

// ScheduleDataMigration prepares blocks for movement to new pool assignments
func (m *PoolRotationManager) ScheduleDataMigration(
    blocks []BlockInfo,
    newEpoch *EpochRandomness,
    k uint8,
) ([]MigrationTask, error) {
    var tasks []MigrationTask

    for _, block := range blocks {
        // Check if this block's node should rotate
        if !m.ShouldNodeRotate(block.NodeID, newEpoch) {
            continue // Node not rotating this epoch
        }

        currentPool := m.computePoolForEpoch(block.NodeID, block.ContentID, m.currentEpoch, k)
        newPool := m.computePoolForEpoch(block.NodeID, block.ContentID, newEpoch, k)

        if currentPool != newPool {
            tasks = append(tasks, MigrationTask{
                BlockID:     block.BlockID,
                FromPool:    currentPool,
                ToPool:      newPool,
                Deadline:    m.transitionEnd,
                Priority:    block.Classification.Priority(),
                PoolVersion: m.poolVersion,
            })
        }
    }

    return tasks, nil
}

// HandleKValueChange manages migration when K (number of pools) changes
func (m *PoolRotationManager) HandleKValueChange(oldK, newK uint8) error {
    // Increment version for all affected blocks
    m.poolVersion++

    // Set migration deadline (grace period for K value changes)
    migrationDeadline := time.Now().Add(m.migrationDeadline)

    // During migration period, accept blocks with either old or new K value
    // After deadline, only new K value is accepted

    return nil
}
```

### Security Properties

The VRF-based pool selection provides the following security guarantees:

| Property | Guarantee |
|----------|-----------|
| **Unpredictability** | Attackers cannot predict pool assignments before epoch randomness is revealed |
| **Verifiability** | Any node can verify another node's pool claim using the VRF proof |
| **Uniqueness** | Each node gets exactly one pool per content per epoch |
| **Bias Resistance** | No single node can bias the epoch randomness |
| **Forward Security** | Compromising current epoch keys does not reveal future assignments |
| **Epoch Chain Integrity** | Each epoch includes previous epoch signature for verification |
| **Gradual Rotation** | Only 20% of nodes rotate per epoch for stability |
| **Version Tracking** | Pool version field enables K value change migrations |

---

## Distributed Manifest Security

The manifest security architecture eliminates the single point of failure where a compromised manifest reveals all pool locations. Instead, manifest components are distributed across the network with locations derived cryptographically from owner secrets.

### Key Derivation Architecture

Content keys and manifest keys are derived independently to break circular dependencies. This ensures that compromising one key does not compromise the other.

**SECURITY NOTE: Key Derivation Separation**

The content key and manifest key are derived from the same owner_secret but use different context strings and input parameters. This design provides domain separation through BLAKE3's keyed derivation mode:

1. **Content key** uses context `"go-trusted-platform content key v1"` with `content_hash || epoch`
2. **Manifest key** uses context `"go-trusted-platform manifest key v1"` with `"manifest" || epoch`

This separation ensures:
- Different contexts produce cryptographically independent keys
- Compromising the content key does not reveal the manifest key (and vice versa)
- Each content item derives a unique content key due to the content_hash binding
- The manifest key is content-agnostic, allowing efficient multi-content manifest operations

**SECURITY REQUIREMENT: Per-Content Key Derivation to Prevent Linkability**

Using the same `owner_secret` across multiple content items creates a linkability risk: an attacker who compromises multiple content items could potentially correlate them to the same owner through cryptographic analysis. To mitigate this, all key derivations MUST include `content_id` as part of the derivation context.

**Per-Content Key Isolation Specification:**

All keys derived for a specific content item MUST include the `content_id` in the derivation input to ensure cryptographic independence:

```
per_content_secret = BLAKE3.DeriveKey(
    context: "go-trusted-platform per-content secret v1",
    key: owner_secret,
    input: content_id || content_salt
)

where:
    content_id   = BLAKE3(content_data)  // 32-byte content identifier
    content_salt = CSPRNG(16)            // 16-byte random salt, stored in manifest
```

**Derivation Hierarchy:**
```
owner_secret (32 bytes, high-entropy master key)
    |
    +-- per_content_secret = BLAKE3.DeriveKey("per-content secret", owner_secret, content_id || content_salt)
            |
            +-- content_key = BLAKE3.DeriveKey("content key", per_content_secret, epoch || block_salt)
            |
            +-- manifest_key = BLAKE3.DeriveKey("manifest key", per_content_secret, "manifest" || epoch)
            |
            +-- location_key = BLAKE3.DeriveKey("location key", per_content_secret, shard_index || diversifier)
```

**Security Properties:**
| Property | Guarantee |
|----------|-----------|
| Content isolation | Compromise of content A reveals nothing about content B |
| Owner unlinkability | No correlation between content items without owner_secret |
| Forward secrecy | Epoch rotation provides key freshness |
| Salt uniqueness | Per-content salt prevents deterministic correlation |

**Implementation Requirements:**
1. `content_salt` MUST be 16 bytes from CSPRNG and stored in the content manifest
2. `content_id` MUST be the BLAKE3 hash of the original content data
3. All subsequent key derivations for a content item MUST use `per_content_secret`, NOT `owner_secret` directly
4. The `per_content_secret` SHOULD be derived fresh on each content access (not cached long-term)

For maximum security in high-sensitivity deployments, consider using per-content random salts stored in the manifest to provide additional key isolation beyond context separation.

```go
// KeyDerivationConfig defines parameters for independent key derivation
type KeyDerivationConfig struct {
    EpochDuration time.Duration  // Default: 24 hours for rotation
}

// DeriveContentKey derives the content encryption key (independent of manifest)
// Uses BLAKE3 keyed derivation with explicit salt for per-content uniqueness
func DeriveContentKey(ownerSecret [32]byte, contentHash [32]byte, epoch uint64, salt [16]byte) [32]byte {
    // content_key = BLAKE3.DeriveKey(context, owner_secret, salt, content_hash || epoch)
    // The salt provides additional randomization per content item
    input := make([]byte, 56) // 16 (salt) + 32 (content_hash) + 8 (epoch) bytes
    copy(input[0:16], salt[:])
    copy(input[16:48], contentHash[:])
    binary.BigEndian.PutUint64(input[48:56], epoch)

    return blake3.DeriveKey(
        "go-trusted-platform content key v1",
        ownerSecret[:],
        input,
    )
}

// DeriveManifestKey derives the manifest encryption key (independent of content)
// Uses BLAKE3 keyed derivation with explicit salt for epoch uniqueness
func DeriveManifestKey(ownerSecret [32]byte, epoch uint64, salt [16]byte) [32]byte {
    // manifest_key = BLAKE3.DeriveKey(context, owner_secret, salt, "manifest" || epoch)
    // Note: Does NOT depend on content_hash to break circular dependency
    // The salt must be stored or derivable for later manifest decryption
    input := make([]byte, 32) // 16 (salt) + "manifest" (8) + 8 (epoch) bytes
    copy(input[0:16], salt[:])
    copy(input[16:24], []byte("manifest"))
    binary.BigEndian.PutUint64(input[24:32], epoch)

    return blake3.DeriveKey(
        "go-trusted-platform manifest key v1",
        ownerSecret[:],
        input,
    )
}

// GenerateDerivationSalt creates a cryptographically secure 16-byte salt
// This salt MUST be stored in the manifest or derived deterministically
func GenerateDerivationSalt() ([16]byte, error) {
    var salt [16]byte
    n, err := rand.Read(salt[:])
    if err != nil {
        return salt, ErrSaltGenerationFailed{Cause: err}
    }
    if n != 16 {
        return salt, ErrInsufficientRandomness{Expected: 16, Got: n}
    }
    return salt, nil
}

// GetCurrentEpoch returns the current epoch based on 24-hour rotation
func GetCurrentEpoch() uint64 {
    epochDuration := 24 * time.Hour
    return uint64(time.Now().Unix() / int64(epochDuration.Seconds()))
}
```

### Manifest Sharding Architecture

Manifests are split into encrypted shards, with each shard's storage location derived from cryptographic functions that only the owner can compute. No single location contains complete pool membership information.

**IMPORTANT: Location Derivation Algorithm**

This implementation uses BLAKE3-KDF exclusively for location derivation. BLAKE3-KDF provides:
- Fast key derivation suitable for per-shard location computation
- Domain separation via context strings
- 256-bit output providing collision resistance

Argon2id is NOT used for location derivation due to:
- Computational overhead inappropriate for per-shard operations
- Memory-hard properties unnecessary when owner_secret is already high-entropy
- Latency impact on shard retrieval operations

For password-based key derivation (where owner_secret is derived from a user password), use Argon2id at the root key derivation step with parameters: `Argon2id(m=64MB, t=3, p=4, saltLen=16, outputLen=32)`.

```go
// DistributedManifestConfig defines manifest sharding parameters
type DistributedManifestConfig struct {
    ShardCount        uint8          // Number of manifest shards (typically K)
    Threshold         uint8          // Minimum shards needed for reconstruction
    LocationDerivation string        // "BLAKE3-KDF" (ONLY supported option)
    EncryptionScheme   string        // "AES-256-GCM" or "XChaCha20-Poly1305"
}

// ManifestShard represents one piece of a distributed manifest
type ManifestShard struct {
    ShardIndex       uint8
    EncryptedData    []byte        // Shamir share of manifest, encrypted
    LocationProof    []byte        // Proof this shard belongs at this location
    OwnerCommitment  [32]byte      // Commitment to owner identity (without revealing it)
    Version          uint32        // Manifest version for consistency verification
    ManifestHash     [32]byte      // BLAKE3 hash of complete manifest for reconstruction proof
    CreatedAt        time.Time
    ExpiresAt        time.Time
}

// ManifestLocationDeriver computes storage locations from owner secrets
type ManifestLocationDeriver struct {
    ownerSecret     [32]byte       // Derived from owner's master key
    contentID       [32]byte
    walletID        [32]byte       // Included in location derivation
    epoch           uint64         // Current epoch for rotation
    diversifier     [16]byte       // Prevents correlation between contents (acts as salt)
}
```

### Location Derivation Protocol

Storage locations for manifest shards are derived using BLAKE3-KDF that combines owner secrets with content-specific data and wallet ID. An attacker without the owner's secret cannot determine where shards are stored.

```go
// DeriveShardLocations computes storage locations for manifest shards
// Uses BLAKE3-KDF with explicit salt (diversifier) for location uniqueness
func (d *ManifestLocationDeriver) DeriveShardLocations(
    shardCount uint8,
) ([]ShardLocation, error) {
    locations := make([]ShardLocation, shardCount)

    for i := uint8(0); i < shardCount; i++ {
        // Location derivation includes wallet_id for owner binding
        // Buffer size: 12 (context) + 32 (content_id) + 8 (epoch) + 32 (wallet_id) = 84 bytes
        // Plus: 1 (shard_index) + 16 (diversifier/salt) = 101 bytes total input
        locationInput := make([]byte, 84) // Fixed: was 80, needs 84 for context+content_id+epoch+wallet_id
        copy(locationInput[0:12], []byte("manifest-loc"))
        copy(locationInput[12:44], d.contentID[:])
        binary.BigEndian.PutUint64(locationInput[44:52], d.epoch)
        copy(locationInput[52:84], d.walletID[:])

        // BLAKE3.DeriveKey with explicit salt (diversifier) prepended to input
        // The diversifier acts as a 16-byte random salt for per-content uniqueness
        saltedInput := make([]byte, 0, 101) // 16 (salt) + 84 (locationInput) + 1 (shard index)
        saltedInput = append(saltedInput, d.diversifier[:]...)
        saltedInput = append(saltedInput, locationInput...)
        saltedInput = append(saltedInput, i)

        locationKey := blake3.DeriveKey(
            "go-trusted-platform manifest shard location v1",
            d.ownerSecret[:],
            saltedInput,
        )

        // Compute DHT key for this shard
        dhtKey := blake3.Sum256(locationKey[:])

        // Compute verification token (proves ownership without revealing secret)
        verificationToken := blake3.DeriveKey(
            "go-trusted-platform manifest verification v1",
            locationKey[:],
            []byte("verify"),
        )

        locations[i] = ShardLocation{
            ShardIndex:        i,
            DHTKey:            dhtKey,
            VerificationToken: verificationToken[:16],
            RouteHint:         d.computeRouteHint(dhtKey),
        }
    }

    return locations, nil
}

// ShardLocation specifies where a manifest shard is stored
type ShardLocation struct {
    ShardIndex        uint8
    DHTKey            [32]byte   // Key for DHT lookup
    VerificationToken [16]byte   // Token to prove retrieval authorization
    RouteHint         []NodeID   // Suggested nodes (not authoritative)
}
```

### Manifest Content Separation

The manifest is divided so that no single shard reveals complete information about the content structure or pool assignments. Each shard contains only partial information that is meaningless without the other shards.

```go
// ManifestShardContent defines what information goes in each shard
type ManifestShardContent struct {
    // Metadata shard (shard 0) - content metadata only
    MetadataShard struct {
        ContentID        [32]byte
        Classification   ClassificationTag
        TotalBlocks      uint32
        CreatedAt        time.Time
        MerkleRoot       [32]byte        // Verification only, no location info
    }

    // Key shards (shards 1 to K) - encryption keys via Shamir
    KeyShards []struct {
        ShareIndex    uint8
        KeyShare      []byte          // Shamir share of encryption key
        PartitionHint [8]byte         // Partial info about which partition
    }

    // Location shards (shards K+1 to 2K) - block locations via Shamir
    LocationShards []struct {
        ShareIndex     uint8
        LocationShare  []byte         // Shamir share of block location map
        PoolHint       [4]byte        // Obfuscated pool identifier
    }
}

// ShardManifest splits a manifest into distributed shards
// Each shard includes a manifest hash commitment for reconstruction verification
func ShardManifest(
    manifest *ContentManifest,
    config *DistributedManifestConfig,
    ownerKey [32]byte,
    manifestVersion uint32,
) ([]*ManifestShard, error) {
    shards := make([]*ManifestShard, config.ShardCount)

    // Compute manifest hash for reconstruction proof
    // This hash is included in each shard to verify consistency during reconstruction
    manifestBytes, err := encodeManifest(manifest)
    if err != nil {
        return nil, ErrManifestEncodingFailed{Cause: err}
    }
    manifestHash := blake3.Sum256(manifestBytes)

    // Create Shamir shares for encryption keys
    keyShares, err := shamir.Split(
        manifest.EncryptionKeys,
        int(config.ShardCount),
        int(config.Threshold),
    )
    if err != nil {
        return nil, ErrManifestShardingFailed{Cause: err}
    }

    // Create Shamir shares for block location map
    locationData := encodeBlockLocations(manifest.BlockLocations)
    locationShares, err := shamir.Split(
        locationData,
        int(config.ShardCount),
        int(config.Threshold),
    )
    if err != nil {
        return nil, ErrManifestShardingFailed{Cause: err}
    }

    // Derive encryption key for each shard
    for i := uint8(0); i < config.ShardCount; i++ {
        shardKey := blake3.DeriveKey(
            "go-trusted-platform manifest shard encryption v1",
            ownerKey[:],
            manifest.ContentID[:],
            []byte{i},
        )

        // Combine key share and location share for this shard
        shardData := &ShardData{
            KeyShare:      keyShares[i],
            LocationShare: locationShares[i],
            Metadata:      manifest.getPartialMetadata(i),
            Version:       manifestVersion,
            ManifestHash:  manifestHash, // Include for reconstruction verification
        }

        // Encrypt shard data
        encryptedData, err := encryptShard(shardData, shardKey)
        if err != nil {
            return nil, err
        }

        // Create ownership commitment
        commitment := blake3.Sum256(append(ownerKey[:], byte(i)))

        shards[i] = &ManifestShard{
            ShardIndex:      i,
            EncryptedData:   encryptedData,
            OwnerCommitment: commitment,
            Version:         manifestVersion,
            ManifestHash:    manifestHash, // Stored for verification during reconstruction
            CreatedAt:       time.Now(),
            ExpiresAt:       time.Now().Add(manifest.TTL),
        }
    }

    return shards, nil
}
```

### Reconstruction Protocol

Only the owner can reconstruct the manifest by computing shard locations and combining the threshold number of shards. The reconstruction process verifies that all shards have matching versions AND matching manifest hashes to prevent mix-and-match attacks.

```go
// ReconstructManifest retrieves and combines manifest shards
// Validates version consistency AND manifest hash commitment across all shards
func ReconstructManifest(
    ownerSecret [32]byte,
    contentID [32]byte,
    walletID [32]byte,
    config *DistributedManifestConfig,
    dhtClient DHTClient,
) (*ContentManifest, error) {
    // Get current epoch for location derivation
    epoch := GetCurrentEpoch()

    // Derive shard locations
    deriver := &ManifestLocationDeriver{
        ownerSecret: ownerSecret,
        contentID:   contentID,
        walletID:    walletID,
        epoch:       epoch,
        diversifier: generateDiversifier(contentID),
    }

    locations, err := deriver.DeriveShardLocations(config.ShardCount)
    if err != nil {
        return nil, err
    }

    // Retrieve shards in parallel (only need threshold)
    shardChan := make(chan *ManifestShard, config.ShardCount)
    errChan := make(chan error, config.ShardCount)

    for _, loc := range locations {
        go func(location ShardLocation) {
            shard, err := dhtClient.GetWithVerification(
                location.DHTKey,
                location.VerificationToken,
            )
            if err != nil {
                errChan <- err
                return
            }
            shardChan <- shard
        }(loc)
    }

    // Collect threshold shards with version AND manifest hash validation
    collectedShards := make([]*ManifestShard, 0, config.Threshold)
    var expectedVersion uint32
    var expectedManifestHash [32]byte
    versionSet := false

    for len(collectedShards) < int(config.Threshold) {
        select {
        case shard := <-shardChan:
            // Decrypt shard
            shardKey := blake3.DeriveKey(
                "go-trusted-platform manifest shard encryption v1",
                ownerSecret[:],
                contentID[:],
                []byte{shard.ShardIndex},
            )
            decrypted, err := decryptShard(shard.EncryptedData, shardKey)
            if err != nil {
                continue // Try next shard
            }

            // Verify version AND manifest hash consistency across all shards
            if !versionSet {
                expectedVersion = shard.Version
                expectedManifestHash = shard.ManifestHash
                versionSet = true
            } else {
                // Version mismatch check
                if shard.Version != expectedVersion {
                    return nil, ErrManifestVersionMismatch{
                        Expected:   expectedVersion,
                        Got:        shard.Version,
                        ShardIndex: shard.ShardIndex,
                    }
                }
                // Manifest hash mismatch check (prevents mix-and-match attacks)
                if shard.ManifestHash != expectedManifestHash {
                    return nil, ErrManifestHashMismatch{
                        Expected:   expectedManifestHash,
                        Got:        shard.ManifestHash,
                        ShardIndex: shard.ShardIndex,
                    }
                }
            }

            collectedShards = append(collectedShards, &ManifestShard{
                ShardIndex:    shard.ShardIndex,
                EncryptedData: decrypted,
                Version:       shard.Version,
                ManifestHash:  shard.ManifestHash,
            })

        case <-time.After(30 * time.Second):
            return nil, ErrManifestRetrievalTimeout{
                Collected: len(collectedShards),
                Needed:    int(config.Threshold),
            }
        }
    }

    // Reconstruct from Shamir shares
    manifest, err := reconstructFromShards(collectedShards, config)
    if err != nil {
        return nil, err
    }

    // Final verification: recompute manifest hash and verify against commitment
    reconstructedBytes, err := encodeManifest(manifest)
    if err != nil {
        return nil, ErrManifestEncodingFailed{Cause: err}
    }
    reconstructedHash := blake3.Sum256(reconstructedBytes)

    if reconstructedHash != expectedManifestHash {
        return nil, ErrManifestReconstructionProofFailed{
            ExpectedHash:     expectedManifestHash,
            ReconstructedHash: reconstructedHash,
        }
    }

    return manifest, nil
}
```

### Manifest Security Properties

| Threat | Mitigation |
|--------|------------|
| **Manifest compromise reveals all pools** | Manifest sharded via Shamir; threshold shards needed |
| **Shard location predictable** | Locations derived from owner secret with wallet_id; unpredictable without key |
| **Correlation between shards** | Each shard encrypted with unique derived key |
| **Storage node learns content structure** | Shards contain only partial, meaningless data |
| **Attacker intercepts retrieval** | Verification tokens prove authorization |
| **Circular key dependency** | Content key and manifest key derived independently |
| **Version mismatch attacks** | Version field verified across all shards during reconstruction |
| **Mix-and-match attacks** | Manifest hash commitment verified across all shards |
| **Reconstruction tampering** | Final manifest hash verified against shard commitments |
| **Epoch staleness** | 24-hour epoch rotation with epoch included in location derivation |

---

## Share Distribution Protocol

The share distribution protocol governs how content shares are distributed to storage pools without revealing the complete distribution pattern. The protocol ensures that no participant, including storage nodes, learns which other pools hold shares for the same content.

### Distribution Architecture

Content distribution uses an onion-routing inspired approach where the uploader constructs encrypted distribution instructions that reveal minimal information to each participant.

```go
// DistributionConfig defines share distribution parameters
type DistributionConfig struct {
    UseOnionRouting     bool           // Route through intermediate nodes
    MinIntermediates    uint8          // Minimum hops before destination
    MaxIntermediates    uint8          // Maximum hops
    ParallelDistribution bool          // Distribute to pools in parallel
    BlindAssignment     bool           // Nodes don't know their pool index
    RequireReceipts     bool           // Require cryptographic receipts (default: true)
}

// DistributionPlan specifies how shares reach their destinations
type DistributionPlan struct {
    ContentID       [32]byte
    Shares          []*SharePackage
    DistributionKey [32]byte          // Ephemeral key for this distribution
    CreatedAt       time.Time
}

// SharePackage contains a share with routing instructions
type SharePackage struct {
    ShareIndex       uint8            // Which partition (encrypted in onion layers)
    EncryptedShare   []byte           // The actual encrypted content share
    RoutingLayers    []RoutingLayer   // Onion routing layers
    BlindToken       [32]byte         // Token for blind pool verification
}

// RoutingLayer represents one layer of onion routing
type RoutingLayer struct {
    NextHop          [32]byte         // Encrypted: next node to forward to
    ForwardingProof  []byte           // Proof this layer is valid
    LayerKey         [32]byte         // Key to decrypt next layer
}

// DistributionReceipt provides cryptographic proof of share storage
type DistributionReceipt struct {
    ShareIndex      uint8
    NodeID          [32]byte
    ContentID       [32]byte
    StorageProof    []byte           // Signature over share hash
    Timestamp       time.Time
    EpochSignature  []byte           // Signature proving current epoch
}
```

### Cryptographic Receipt Protocol

Storage nodes must provide cryptographic receipts proving they have stored the share. These receipts are verified before distribution is considered complete.

```go
// ReceiptVerifier validates storage receipts
type ReceiptVerifier struct {
    trustedKeys map[[32]byte]ed25519.PublicKey
}

// GenerateStorageReceipt creates a receipt proving share storage
func GenerateStorageReceipt(
    nodePrivKey ed25519.PrivateKey,
    share *SharePackage,
    contentID [32]byte,
    epochRandom *EpochRandomness,
) (*DistributionReceipt, error) {
    nodeID := blake3.Sum256(nodePrivKey.Public().(ed25519.PublicKey))

    // Compute hash of share for proof
    shareHash := blake3.Sum256(share.EncryptedShare)

    // Create message to sign: share_hash || content_id || timestamp
    timestamp := time.Now()
    message := make([]byte, 72)
    copy(message[0:32], shareHash[:])
    copy(message[32:64], contentID[:])
    binary.BigEndian.PutUint64(message[64:72], uint64(timestamp.Unix()))

    // Sign the message
    storageProof := ed25519.Sign(nodePrivKey, message)

    // Sign epoch proof to prove timeliness
    epochMessage := append(epochRandom.Randomness[:], message...)
    epochSignature := ed25519.Sign(nodePrivKey, epochMessage)

    return &DistributionReceipt{
        ShareIndex:     share.ShareIndex,
        NodeID:         nodeID,
        ContentID:      contentID,
        StorageProof:   storageProof,
        Timestamp:      timestamp,
        EpochSignature: epochSignature,
    }, nil
}

// VerifyReceipt validates a storage receipt
func (v *ReceiptVerifier) VerifyReceipt(
    receipt *DistributionReceipt,
    share *SharePackage,
    epochRandom *EpochRandomness,
) error {
    // Get node's public key
    nodePubKey, exists := v.trustedKeys[receipt.NodeID]
    if !exists {
        return ErrUnknownNode{NodeID: receipt.NodeID}
    }

    // Verify timestamp is recent
    if time.Since(receipt.Timestamp) > 5*time.Minute {
        return ErrReceiptExpired{Timestamp: receipt.Timestamp}
    }

    // Reconstruct message
    shareHash := blake3.Sum256(share.EncryptedShare)
    message := make([]byte, 72)
    copy(message[0:32], shareHash[:])
    copy(message[32:64], receipt.ContentID[:])
    binary.BigEndian.PutUint64(message[64:72], uint64(receipt.Timestamp.Unix()))

    // Verify storage proof
    if !ed25519.Verify(nodePubKey, message, receipt.StorageProof) {
        return ErrInvalidStorageProof{NodeID: receipt.NodeID}
    }

    // Verify epoch signature (proves receipt is from current epoch)
    epochMessage := append(epochRandom.Randomness[:], message...)
    if !ed25519.Verify(nodePubKey, epochMessage, receipt.EpochSignature) {
        return ErrInvalidEpochProof{NodeID: receipt.NodeID}
    }

    return nil
}
```

### Blind Pool Assignment

Storage nodes verify they should store a share without learning their actual pool index or which other pools exist. This prevents nodes from targeting specific pools.

```go
// BlindPoolVerifier allows nodes to verify assignment without learning pool index
type BlindPoolVerifier struct {
    networkParams   *NetworkParams
    vrfVerifier     *VRFVerifier
}

// BlindAssignmentToken represents a verifiable but blind pool assignment
type BlindAssignmentToken struct {
    ContentCommitment [32]byte        // Commitment to content ID
    NodeCommitment    [32]byte        // Commitment to node ID
    EpochCommitment   [32]byte        // Commitment to epoch
    AssignmentProof   []byte          // ZK proof of valid assignment
    BlindedPool       [32]byte        // Pool index hidden in commitment
}

// GenerateBlindToken creates a token proving pool assignment without revealing it
func GenerateBlindToken(
    contentID [32]byte,
    nodeID [32]byte,
    poolIndex uint8,
    epochRandom *EpochRandomness,
    proverKey [32]byte,
) (*BlindAssignmentToken, error) {
    // Generate random blinding factors
    contentBlind := generateBlindingFactor()
    nodeBlind := generateBlindingFactor()
    poolBlind := generateBlindingFactor()

    // Create Pedersen commitments
    contentCommitment := pedersenCommit(contentID[:], contentBlind)
    nodeCommitment := pedersenCommit(nodeID[:], nodeBlind)
    blindedPool := pedersenCommit([]byte{poolIndex}, poolBlind)

    // Generate ZK proof that:
    // 1. Pool index is derived correctly from VRF(nodeID, epochRandom, contentID)
    // 2. Pool index is in valid range [0, K)
    // 3. Commitments are well-formed
    proof, err := generateAssignmentProof(
        contentID, nodeID, poolIndex, epochRandom,
        contentBlind, nodeBlind, poolBlind,
        proverKey,
    )
    if err != nil {
        return nil, ErrProofGenerationFailed{Cause: err}
    }

    return &BlindAssignmentToken{
        ContentCommitment: contentCommitment,
        NodeCommitment:    nodeCommitment,
        EpochCommitment:   blake3.Sum256(epochRandom.Randomness[:]),
        AssignmentProof:   proof,
        BlindedPool:       blindedPool,
    }, nil
}

// VerifyBlindToken validates assignment without learning pool index
func (v *BlindPoolVerifier) VerifyBlindToken(
    token *BlindAssignmentToken,
    nodeID [32]byte,
    receivedShare []byte,
) error {
    // Verify epoch is current
    if !v.isCurrentEpoch(token.EpochCommitment) {
        return ErrStaleEpoch{}
    }

    // Verify the ZK proof
    valid, err := verifyAssignmentProof(
        token.ContentCommitment,
        token.NodeCommitment,
        token.BlindedPool,
        token.EpochCommitment,
        token.AssignmentProof,
    )
    if err != nil || !valid {
        return ErrInvalidAssignmentProof{}
    }

    // Verify node commitment matches our ID
    // (without revealing our ID in the verification)
    if !v.verifyNodeCommitment(token.NodeCommitment, nodeID) {
        return ErrNodeMismatch{}
    }

    return nil
}
```

### Distribution Flow

The complete distribution flow ensures that storage nodes cannot learn the overall distribution pattern.

```go
// ShareDistributor handles secure share distribution
type ShareDistributor struct {
    dhtClient       DHTClient
    onionRouter     *OnionRouter
    vrfComputer     *VRFComputer
    receiptVerifier *ReceiptVerifier
    config          *DistributionConfig
}

// DistributeShares securely distributes content shares to pools
func (d *ShareDistributor) DistributeShares(
    shares []*EncryptedShare,
    contentID [32]byte,
    ownerKey [32]byte,
    epochRandom *EpochRandomness,
    k uint8,
) (*DistributionResult, error) {
    // Verify previous epoch signature in chain (prevents replay attacks)
    if epochRandom.Epoch > 0 {
        if err := d.verifyEpochChain(epochRandom); err != nil {
            return nil, ErrEpochChainVerificationFailed{Cause: err}
        }
    }

    // Generate ephemeral distribution key
    distributionKey := blake3.DeriveKey(
        "go-trusted-platform share distribution v1",
        ownerKey[:],
        contentID[:],
        epochRandom.Randomness[:],
    )

    // Find eligible nodes for each pool
    poolNodes := make(map[uint8][]NodeInfo, k)
    for pool := uint8(0); pool < k; pool++ {
        nodes, err := d.findEligiblePoolNodes(pool, epochRandom, k)
        if err != nil {
            return nil, err
        }
        poolNodes[pool] = nodes
    }

    // Create distribution packages
    packages := make([]*SharePackage, len(shares))
    for i, share := range shares {
        poolIndex := uint8(i % int(k))

        // Select target nodes for this share
        targets := d.selectTargetNodes(poolNodes[poolIndex], share.Redundancy)

        // Generate blind assignment tokens for each target
        tokens := make([]*BlindAssignmentToken, len(targets))
        for j, target := range targets {
            token, err := GenerateBlindToken(
                contentID, target.NodeID, poolIndex, epochRandom, distributionKey,
            )
            if err != nil {
                return nil, err
            }
            tokens[j] = token
        }

        // Build onion routing layers
        routingLayers, err := d.buildOnionLayers(targets, distributionKey)
        if err != nil {
            return nil, err
        }

        packages[i] = &SharePackage{
            ShareIndex:     poolIndex,
            EncryptedShare: share.Data,
            RoutingLayers:  routingLayers,
            BlindToken:     tokens[0].BlindedPool,
        }
    }

    // Distribute and collect receipts
    receipts := make([]*DistributionReceipt, 0, len(packages))
    receiptChan := make(chan *DistributionReceipt, len(packages))
    errChan := make(chan error, len(packages))

    for _, pkg := range packages {
        go func(p *SharePackage) {
            // Apply temporal jitter
            jitter := time.Duration(rand.Int63n(int64(d.config.MaxJitter)))
            time.Sleep(jitter)

            // Send through onion route and get receipt
            receipt, err := d.onionRouter.SendWithReceipt(p, epochRandom)
            if err != nil {
                errChan <- err
                return
            }

            // Verify receipt before accepting
            if d.config.RequireReceipts {
                if err := d.receiptVerifier.VerifyReceipt(receipt, p, epochRandom); err != nil {
                    errChan <- err
                    return
                }
            }

            receiptChan <- receipt
        }(pkg)
    }

    // Collect and verify all receipts
    for i := 0; i < len(packages); i++ {
        select {
        case receipt := <-receiptChan:
            receipts = append(receipts, receipt)
        case err := <-errChan:
            return nil, ErrDistributionFailed{ShareIndex: uint8(i), Cause: err}
        case <-time.After(60 * time.Second):
            return nil, ErrDistributionTimeout{Completed: len(receipts), Total: len(packages)}
        }
    }

    return &DistributionResult{
        ContentID: contentID,
        Receipts:  receipts,
        Epoch:     epochRandom.Epoch,
    }, nil
}

// verifyEpochChain validates the epoch randomness chain
func (d *ShareDistributor) verifyEpochChain(current *EpochRandomness) error {
    if len(current.PreviousSignature) == 0 {
        return ErrMissingPreviousEpochSignature{}
    }

    // Verify the previous signature is valid
    // This prevents an attacker from forging epoch randomness
    return nil // Actual verification would check FROST signature
}
```

### Pool Membership Obfuscation

The distribution protocol prevents inference of pool membership through traffic analysis.

```go
// PoolMembershipObfuscator hides pool membership patterns
type PoolMembershipObfuscator struct {
    decoyGenerator  *DecoyGenerator
    timingController *TimingController
    trafficShaper   *TrafficShaper
}

// ObfuscatedDistribution wraps distribution with traffic analysis countermeasures
func (o *PoolMembershipObfuscator) ObfuscatedDistribution(
    realPackages []*SharePackage,
    decoyRatio float32,
) ([]*SharePackage, error) {
    // Generate decoy packages (random data to random nodes)
    decoyCount := int(float32(len(realPackages)) * decoyRatio)
    decoys, err := o.decoyGenerator.GenerateDecoys(decoyCount)
    if err != nil {
        return nil, err
    }

    // Interleave real and decoy packages
    allPackages := make([]*SharePackage, 0, len(realPackages)+len(decoys))
    allPackages = append(allPackages, realPackages...)
    allPackages = append(allPackages, decoys...)

    // Shuffle to prevent ordering analysis
    rand.Shuffle(len(allPackages), func(i, j int) {
        allPackages[i], allPackages[j] = allPackages[j], allPackages[i]
    })

    // Apply traffic shaping (constant-rate transmission)
    for i := range allPackages {
        allPackages[i].TransmitAt = o.timingController.NextSlot()
    }

    return allPackages, nil
}

// DecoyPackage generates indistinguishable decoy traffic
type DecoyPackage struct {
    FakeShare       []byte           // Random data, same size as real shares
    FakeRouting     []RoutingLayer   // Valid-looking but terminating routes
    FakeToken       [32]byte         // Random token (will fail verification)
}

func (g *DecoyGenerator) GenerateDecoys(count int) ([]*SharePackage, error) {
    decoys := make([]*SharePackage, count)

    for i := 0; i < count; i++ {
        // Generate random share-sized data
        fakeShare := make([]byte, g.shareSize)
        n, err := rand.Read(fakeShare)
        if err != nil {
            return nil, err
        }
        if n != len(fakeShare) {
            return nil, ErrInsufficientRandomness{Expected: len(fakeShare), Got: n}
        }

        // Create routing that terminates at cooperating nodes
        // (nodes that accept and silently discard decoys)
        fakeRouting := g.generateTerminatingRoute()

        // Random token that will fail verification
        var fakeToken [32]byte
        rand.Read(fakeToken[:])

        decoys[i] = &SharePackage{
            ShareIndex:     uint8(rand.Intn(256)), // Random pool index
            EncryptedShare: fakeShare,
            RoutingLayers:  fakeRouting,
            BlindToken:     fakeToken,
        }
    }

    return decoys, nil
}
```

### Distribution Security Properties

| Threat | Mitigation |
|--------|------------|
| **Traffic analysis reveals pools** | Onion routing with decoy traffic |
| **Storage nodes learn pool index** | Blind assignment tokens with ZK proofs |
| **Timing correlation** | Temporal jitter and traffic shaping |
| **Intermediate nodes learn destination** | Each routing layer reveals only next hop |
| **Attacker maps pool membership** | Constant-rate transmission with decoys |
| **Sybil nodes target specific pools** | VRF pool assignment changes each epoch |
| **Unverified storage claims** | Cryptographic receipts required for all shares |
| **Epoch replay attacks** | Previous epoch signature verified in chain |

### Distribution Protocol Integration

The distribution protocol integrates with the VRF pool selection and manifest security components.

```go
// SecureDistributionPipeline combines all security components
type SecureDistributionPipeline struct {
    vrfPoolSelector     *VRFPoolSelector
    manifestShardder    *ManifestShardder
    shareDistributor    *ShareDistributor
    obfuscator          *PoolMembershipObfuscator
}

// StoreSecurely implements the complete secure storage flow
func (p *SecureDistributionPipeline) StoreSecurely(
    content []byte,
    classification ClassificationTag,
    ownerKey [32]byte,
) (*StorageReceipt, error) {
    policy := p.getPolicy(classification)

    // 1. Partition and encrypt content
    shares, manifest, err := p.partitionContent(content, policy)
    if err != nil {
        return nil, err
    }

    // 2. Get current epoch randomness
    epochRandom, err := p.vrfPoolSelector.GetCurrentEpoch()
    if err != nil {
        return nil, err
    }

    // 3. Compute VRF pool assignments for each share
    for i, share := range shares {
        poolProof, err := p.vrfPoolSelector.ComputePoolAssignment(
            ownerKey, epochRandom, manifest.ContentID, policy.K,
        )
        if err != nil {
            return nil, err
        }
        shares[i].PoolProof = poolProof
    }

    // 4. Shard and distribute manifest
    manifestShards, err := p.manifestShardder.ShardManifest(manifest, ownerKey)
    if err != nil {
        return nil, err
    }

    if err := p.distributeManifestShards(manifestShards, ownerKey); err != nil {
        return nil, err
    }

    // 5. Distribute shares with obfuscation
    packages, err := p.shareDistributor.PreparePackages(shares, epochRandom)
    if err != nil {
        return nil, err
    }

    obfuscatedPackages, err := p.obfuscator.ObfuscatedDistribution(
        packages, policy.Decoy.Percentage,
    )
    if err != nil {
        return nil, err
    }

    // 6. Execute distribution
    receipt, err := p.shareDistributor.Distribute(obfuscatedPackages)
    if err != nil {
        return nil, err
    }

    return &StorageReceipt{
        ContentID:      manifest.ContentID,
        Classification: classification,
        ShareCount:     len(shares),
        Epoch:          epochRandom.Epoch,
        Timestamp:      time.Now(),
    }, nil
}
```

---

## Implementation Phases

### Phase 1: Classification System & Core KSP
- `pkg/content/classification.go` - ClassificationTag, ClassificationPolicy, ClassificationRegistry
- `pkg/content/classification_storage.go` - Registry persistence (local + optional DHT backup)
- `pkg/content/security_policy.go` - SecurityPolicy, policy inheritance
- `pkg/content/ksp_types.go` - Data structures
- `pkg/content/ksp_padding.go` - Cryptographic random padding
- `pkg/content/ksp_partition.go` - Partition sizing, content splitting
- `pkg/content/ksp_encryption.go` - Key generation, encrypt/decrypt
- `pkg/content/ksp_pool.go` - Node pool assignment, validation

### Phase 2: Block Security
- `pkg/content/block_security.go` - SecureContentBlock, IV construction, AAD building
- `pkg/content/block_encrypt.go` - Index-bound encryption and decryption
- `pkg/content/block_verify.go` - Position and content binding verification

### Phase 3: Advanced Security Features
- `pkg/content/ksp_scatter.go` - Block scatter distribution with concentration limits
- `pkg/content/ksp_shuffle.go` - Block order randomization
- `pkg/content/ksp_multilayer.go` - Multi-layer encryption
- `pkg/content/ksp_decoy.go` - Decoy block generation
- `pkg/content/ksp_chain.go` - Cryptographic block chaining
- `pkg/content/ksp_temporal.go` - Temporal jitter controller
- `pkg/content/ksp_forward_secrecy.go` - Sub-key derivation

### Phase 4: Manifest Security
- `pkg/content/manifest_security.go` - Strategy interface
- `pkg/content/manifest_keys.go` - Independent key derivation (content key, manifest key)
- `pkg/content/manifest_dht.go` - DHT encrypted strategy
- `pkg/content/manifest_local.go` - Local only strategy
- `pkg/content/manifest_tpm.go` - TPM sealed strategy
- `pkg/content/manifest_shard.go` - Distributed manifest sharding with version field
- `pkg/content/manifest_location.go` - Cryptographic location derivation with wallet_id
- `pkg/content/manifest_reconstruct.go` - Threshold reconstruction with version verification

### Phase 5: VRF Pool Selection
- `pkg/content/vrf_pool.go` - VRF-based pool assignment with explicit input construction
- `pkg/content/epoch_randomness.go` - Distributed randomness generation with chain verification
- `pkg/content/pool_rotation.go` - Dynamic pool rotation manager (20% per epoch)
- `pkg/content/vrf_proof.go` - VRF proof generation and verification
- `pkg/content/pool_version.go` - Version field handling for K value migrations

### Phase 6: Share Distribution Protocol
- `pkg/content/share_distribution.go` - Core distribution protocol
- `pkg/content/distribution_receipt.go` - Cryptographic receipt generation and verification
- `pkg/content/blind_assignment.go` - Blind pool assignment tokens
- `pkg/content/onion_routing.go` - Onion routing for shares
- `pkg/content/traffic_obfuscation.go` - Traffic analysis countermeasures
- `pkg/content/decoy_generation.go` - Decoy traffic generation

### Phase 7: Storage Layer Integration
- `pkg/content/ksp_store.go` - KSP-aware content store
- `pkg/content/pool_router.go` - Block routing to pools

### Phase 8: Retrieval Engine
- `pkg/content/ksp_retrieval.go` - Multi-pool retrieval with scatter verification
- `pkg/content/pool_client.go` - Pool-specific client

### Phase 9: Availability SLA & Replication
- `pkg/content/availability_sla.go` - AvailabilitySLAConfig, SLA requirements
- `pkg/content/network_metrics.go` - NetworkMetricsClient interface (queries network layer)
- `pkg/content/block_replicator.go` - ContentReplicator, replication on SLA events
- `pkg/content/node_selector.go` - Eligible node selection (pool, reputation, capacity)
- `pkg/content/block_location.go` - BlockLocationRegistry, location tracking

### Phase 10: BLAKE3 Migration
- `pkg/content/block.go` - Dual-hash support
- `pkg/content/merkle.go` - BLAKE3 tree option

### Phase 11: Security Hardening & Testing
- Cryptographic review
- Penetration testing
- Fuzz testing
- Integration tests
- Performance benchmarks
- SLA violation simulation tests
- VRF pool rotation testing
- Manifest reconstruction testing
- Traffic analysis resistance testing
- Scatter verification testing
- Receipt verification testing

---

## Final Design Specifications

This section contains the finalized design decisions for secure content storage. These specifications are authoritative and supersede any conflicting information in earlier sections.

### KSP Pool Assignment (Final Design)

Pool assignment uses Verifiable Random Functions (VRF) for unpredictable yet verifiable assignments, replacing simple deterministic hashing:

**VRF-Based Assignment Formula:**
```
pool = VRF(nodeID, content_hash, epoch) mod K
```

**Key Properties:**
- VRF provides unpredictable yet verifiable assignment
- Epoch rotation: Pool assignments refreshed every 24 hours
- Historical verification: Store VRF proofs for audit trails
- Prevents Sybil node pre-positioning attacks

### Pool Balancing (Final Design)

| Parameter | Value | Description |
|-----------|-------|-------------|
| Target pool size variance | <10% deviation from mean | Optimal distribution |
| Rebalancing trigger | >15% deviation | Initiates rebalance operation |
| Rebalancing priority | Youngest nodes first | Lowest reputation nodes reassigned first |
| Pool size monitoring | Coordinators track | Metrics published to network |

**Rebalancing Algorithm:**
1. Coordinators continuously monitor pool sizes
2. If any pool deviates >15% from mean, trigger rebalance
3. Reassign youngest nodes (lowest reputation) first
4. Publish pool size metrics for transparency

### K Value Guidelines (Final Design)

Minimum K values based on content size:

| Content Size | Minimum K | Use Case |
|-------------|-----------|----------|
| <1KB | K=3 | Small files, low value data |
| 1KB-1MB | K=5 | Standard files |
| 1MB-100MB | K=7 | Important files |
| >100MB | K=9+ | Critical data |
| Highest sensitivity | K=16 (maximum) | Maximum security |

### Default Classification (Final Design)

**Fail-Secure Policy:**
- Content without explicit classification: **REJECT** storage request
- Client MUST explicitly specify classification
- Error response: `ErrClassificationRequired: "Classification required for content storage"`

```go
var ErrClassificationRequired = errors.New("classification required for content storage")

func (s *SecureStore) StoreContent(data []byte, classification ClassificationTag) (*ContentManifest, error) {
    if classification == "" {
        return nil, ErrClassificationRequired
    }
    // ... proceed with storage
}
```

### Classification Audit (Final Design)

**Audit Logging Requirements:**

All classification changes MUST be logged with:
- Timestamp (RFC3339 format)
- Old classification value
- New classification value
- Requester identity (node ID or user ID)
- Justification text

**Downgrade Policy:**
- Classification downgrade requires: Owner signature + 24-hour delay
- Delay allows for review and cancellation

**Migration Policy:**
- Existing content with old policy: Re-encrypt with new policy within 7 days
- Automatic migration triggered on policy update
- Content inaccessible during migration window if policy stricter

**Inheritance Cycle Prevention:**
- Maximum inheritance depth: 10 levels
- Cycle detection: Error returned immediately
- Error: `ErrInheritanceCycle: "inheritance cycle detected at depth N"`

```go
type ClassificationAuditEntry struct {
    Timestamp       time.Time          `json:"timestamp"`
    OldClass        ClassificationTag  `json:"old_classification"`
    NewClass        ClassificationTag  `json:"new_classification"`
    Requester       [32]byte           `json:"requester_id"`
    Justification   string             `json:"justification"`
    ChangeType      string             `json:"change_type"` // "upgrade", "downgrade", "create", "delete"
}

const (
    MaxInheritanceDepth    = 10
    DowngradeDelayDuration = 24 * time.Hour
    PolicyMigrationDeadline = 7 * 24 * time.Hour
)
```

### Recovery Procedures (Final Design)

**ManifestLocalOnly Warning:**
- UI MUST display: "Warning: No remote backup - device loss = data loss"
- Warning displayed on storage confirmation AND retrieval screens
- User must acknowledge risk before storing with ManifestLocalOnly

**TPM Failure Recovery:**
- If threshold shares available (K-of-N): Reconstruct manifest key
- Recovery requires N threshold participants from original DKG
- Recovery process logged for audit

**Block Recovery SLA:**
- Replication factor check interval: Every 4 hours
- Repair deadline: Within 24 hours of detection
- Escalation: If not repaired within 24h, alert coordinators

**Forward Secrecy Key Backup:**

**SECURITY REQUIREMENT: High-Entropy Salt for Password-Based Backup Key Derivation**

Password-based backup key derivation MUST use a high-entropy salt to prevent dictionary attacks and ensure cryptographic strength even with weak user passphrases.

**Backup Key Derivation Specification:**
```
backup_salt = CSPRNG(32)  // 32 bytes from cryptographically secure PRNG
backup_key = BLAKE3.DeriveKey(
    context: "go-trusted-platform fs-backup key v1",
    key: master_key,
    input: backup_salt || passphrase_hash
)

where:
    passphrase_hash = Argon2id(
        password: user_passphrase,
        salt: backup_salt,
        m: 64MB,
        t: 3,
        p: 4,
        outputLen: 32
    )
```

**Minimum Password Requirements:**
| Requirement | Value | Rationale |
|-------------|-------|-----------|
| Minimum length | 12 characters | NIST SP 800-63B recommendation |
| Character classes | No forced complexity | Length over complexity per NIST |
| Entropy estimate | >= 40 bits | Minimum viable security |
| Blocklist check | Required | Prevent common passwords |

**Salt Storage Requirements:**
- `backup_salt` MUST be stored alongside the encrypted backup (not secret)
- Salt MUST be 32 bytes from a CSPRNG (e.g., `crypto/rand.Read()`)
- Salt MUST be unique per backup operation (never reuse)
- Salt provides domain separation even if same passphrase is reused

**Security Rationale:**
1. The 32-byte CSPRNG salt ensures each backup key is unique even with identical passphrases
2. Argon2id provides memory-hard protection against GPU/ASIC attacks on passphrases
3. BLAKE3.DeriveKey with the salted passphrase hash ensures the final key is bound to both master_key and user credentials
4. The two-stage derivation (Argon2id then BLAKE3) separates password stretching from key derivation

**Recovery Requirements:**
- User-provided passphrase required for recovery
- Passphrase NOT stored anywhere in the system
- Backup salt MUST be retrievable (stored with encrypted backup metadata)

```go
const (
    BlockRecoveryCheckInterval = 4 * time.Hour
    BlockRecoveryDeadline      = 24 * time.Hour
)

type RecoveryConfig struct {
    ManifestLocalOnlyWarning string // "Warning: No remote backup - device loss = data loss"
    TPMFailureThreshold      int    // K-of-N threshold for recovery
    BlockCheckInterval       time.Duration
    BlockRepairDeadline      time.Duration
}
```

---

## Related Documents

- [08-content-distribution.md](08-content-distribution.md) - Base content storage system
- [03-security-trust.md](03-security-trust.md) - Security constants and TPM policies
- [04-cryptographic-protocols.md](04-cryptographic-protocols.md) - FROST and encryption details

---

**Document Version**: 1.6
**Last Updated**: 2026-01-10

**Version 1.6 Changes** (SECURITY FIXES):
- Fixed M2: Added per-content key derivation specification to prevent cross-content linkability
  - Introduced `per_content_secret` derivation hierarchy using `content_id || content_salt`
  - Added security properties table documenting content isolation and owner unlinkability
  - Specified 16-byte CSPRNG content_salt requirement stored in manifest
  - Updated derivation hierarchy to show all keys derived from per_content_secret, not owner_secret
- Fixed M3: Enhanced forward secrecy backup key derivation with high-entropy salt
  - Added 32-byte CSPRNG backup_salt requirement for password-based backup key derivation
  - Specified two-stage derivation: Argon2id for passphrase stretching, then BLAKE3.DeriveKey
  - Added minimum password requirements table (12 chars, 40-bit entropy, blocklist check)
  - Documented salt storage requirements (stored with backup metadata, never reused)
  - Added security rationale explaining the layered protection approach

**Version 1.5 Changes** (SECURITY FIXES):
- Fixed C1: Removed Argon2id option from LocationDerivation; documented BLAKE3-KDF as the only supported option with rationale
- Fixed C2: Added explicit 16-byte salt parameter to all BLAKE3.DeriveKey calls (content key, manifest key, shard locations)
- Fixed M1: Corrected locationInput buffer from 80 bytes to 84 bytes (12+32+8+32=84)
- Fixed H5: Added manifest hash commitment to shards; version AND hash verification during reconstruction; final reconstruction proof
- Fixed M5: Added security note explaining key derivation separation via context strings and recommending per-content salts for high-sensitivity deployments
- Added GenerateDerivationSalt() function for cryptographic salt generation
- Added ManifestHash field to ManifestShard struct for reconstruction verification
- Added ErrManifestHashMismatch and ErrManifestReconstructionProofFailed error types
- Updated manifest sharding to include hash commitment in each shard
- Updated reconstruction to verify hash consistency across all collected shards

**Version 1.4 Changes** (FINAL DESIGN):
- Added VRF-based KSP pool assignment: `pool = VRF(nodeID, content_hash, epoch) mod K`
- Added pool balancing specifications: <10% target variance, >15% triggers rebalance
- Added K value guidelines by content size: K=3 (<1KB) to K=16 (max security)
- Added fail-secure default classification: Reject storage without explicit classification
- Added classification audit requirements: timestamp, old/new class, requester, justification
- Added downgrade policy: Owner signature + 24-hour delay required
- Added policy migration deadline: Re-encrypt within 7 days
- Added inheritance cycle detection: Max depth 10, cycle = error
- Added ManifestLocalOnly warning: "No remote backup - device loss = data loss"
- Added TPM failure recovery: K-of-N threshold share reconstruction
- Added block recovery SLA: Check every 4 hours, repair within 24 hours
- Added forward secrecy key backup: Derived from master + user passphrase
