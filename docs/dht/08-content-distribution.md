# Content Distribution System

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.
## Overview

The Content Distribution System provides comprehensive infrastructure for storing, distributing, and verifying large files across the trusted DHT network. It encompasses four integrated subsystems:

1. **Content Storage**: Block chunking, Merkle trees, and P2P swarm distribution
2. **Network Boot**: iPXE boot chain with UEFI Secure Boot and TPM measured boot
3. **Update System**: Atomic updates with rollback and FROST-signed manifests
4. **Git Repository**: Foundation-approved storage with 3-of-5 approval workflow

All subsystems share common primitives: 1MB block chunking, SHA-256 hashing, Merkle tree verification, and FROST threshold signatures.

---

## Content Storage System

**Source**: `pkg/content/`

### Block Chunking (1MB Blocks)

Files are split into 1MB blocks with SHA-256 hashing for integrity verification.

```go
type ContentBlock struct {
    Index     uint32              // Block index (0-based)
    Hash      [32]byte            // SHA-256 hash of Data
    Data      []byte              // Block content (<=1MB)
    Size      uint64              // Data length in bytes
    Timestamp time.Time           // Creation timestamp
    Signature []byte              // Optional cryptographic signature
    Metadata  map[string]string   // Key-value metadata
}
```

**Chunking Process**:

```go
// Split large file into 1MB blocks
blocks, err := content.ChunkFile(reader, content.ContentTypeOSImage, metadata)

// Each block is hashed with SHA-256
block.Hash = sha256.Sum256(block.Data)

// Verify block integrity
if !block.Verify() {
    return ErrInvalidBlock
}
```

**Implementation**: `pkg/content/block.go`

### Merkle Trees for Integrity

Blocks are organized into a Merkle tree for efficient verification.

```go
type MerkleTree struct {
    root   []byte       // Root hash (32 bytes)
    leaves [][]byte     // Leaf hashes (block hashes)
    tree   [][][]byte   // Complete tree (indexed by level)
}

type MerkleProof struct {
    Index  int         // Block index
    Hashes [][]byte    // Sibling hashes (path to root)
    Path   []bool      // Navigation (true=right, false=left)
}
```

**Tree Operations**:

```go
// Build Merkle tree from block hashes
blockHashes := extractHashes(blocks)
tree, err := content.BuildTree(blockHashes)

// Generate proof for block at index
proof, err := tree.GenerateProof(blockIndex)

// Verify block without full dataset
err = tree.VerifyProof(blockHash, proof)
```

**Implementation**: `pkg/content/merkle.go`

### P2P Swarm Distribution

BitTorrent-style swarming with intelligent peer selection and rarest-first block distribution.

```go
type Swarm struct {
    ManifestHash [32]byte              // File identifier
    Peers        map[string]*SwarmPeer // Known peers
    HaveBlocks   []bool                // Blocks we have
    WantBlocks   []bool                // Blocks we need
    BlockCount   uint32                // Total blocks
    blockRarity  map[uint32]int        // Rarity cache
}

type SwarmPeer struct {
    NodeID     string
    HasBlocks  []uint32
    Bandwidth  uint64     // bytes/sec
    Reputation float64    // 0.0-1.0
    LastSeen   time.Time
}
```

**Peer Selection Algorithm**:

```go
// Select best peer for block (reputation + bandwidth scoring)
peer := swarm.SelectPeerForBlock(blockIndex)
// Score = (reputation * 0.7) + (bandwidth * 0.3)

// Get missing blocks (rarest-first order)
missing := swarm.MissingBlocks()

// Download blocks from swarm
for _, blockIndex := range missing {
    peer := swarm.SelectPeerForBlock(blockIndex)
    block := downloadBlock(peer, blockIndex)
    swarm.MarkBlockReceived(blockIndex)
}
```

**Implementation**: `pkg/content/swarm.go`

### Replica Node Selection Algorithm

Content blocks are replicated across multiple DHT nodes to ensure availability and fault tolerance. The replica node selection algorithm determines which nodes store copies of each content block.

**Selection Criteria**:

Replica nodes are selected using a multi-factor algorithm that balances proximity, diversity, and reliability:

```go
type ReplicaSelector struct {
    ReplicationFactor    int     // Number of replicas (default: 3)
    MinReputation        float64 // Minimum node reputation (default: 0.5)
    MaxNodesPerASN       int     // ASN diversity limit (default: 2)
    MaxNodesPerRegion    int     // Geographic diversity limit (default: 2)
    FallbackThreshold    int     // Min qualified nodes before fallback (default: 5)
}
```

**Algorithm Steps**:

1. **Distance Calculation**: Compute XOR distance from content hash to all known node IDs
   ```go
   // XOR metric: closer nodes have smaller distance values
   distance := XOR(contentHash, nodeID)
   // Lower distance = higher priority for replica storage
   ```

2. **Candidate Filtering**: Remove nodes below minimum reputation threshold
   ```go
   // Filter candidates
   for _, node := range candidates {
       if node.Reputation < MinReputation {
           continue // Skip unreliable nodes
       }
       qualified = append(qualified, node)
   }
   ```

3. **Distance-Based Ordering**: Sort qualified candidates by XOR distance (ascending)
   ```go
   // Sort by XOR distance to content hash
   sort.Slice(qualified, func(i, j int) bool {
       return XOR(contentHash, qualified[i].NodeID) < XOR(contentHash, qualified[j].NodeID)
   })
   ```

4. **Diversity Enforcement**: Select nodes while enforcing ASN and geographic limits
   ```go
   // Track diversity constraints
   asnCount := make(map[uint32]int)    // ASN -> count
   regionCount := make(map[string]int) // Region -> count

   for _, candidate := range qualified {
       // Check ASN diversity (max 2 replicas per ASN)
       if asnCount[candidate.ASN] >= MaxNodesPerASN {
           continue
       }
       // Check geographic diversity (max 2 replicas per region)
       if regionCount[candidate.Region] >= MaxNodesPerRegion {
           continue
       }

       selected = append(selected, candidate)
       asnCount[candidate.ASN]++
       regionCount[candidate.Region]++

       if len(selected) >= ReplicationFactor {
           break
       }
   }
   ```

5. **Fallback Strategy**: When insufficient qualified nodes exist
   ```go
   // Fallback when fewer than FallbackThreshold qualified nodes
   if len(qualified) < FallbackThreshold {
       // Relax constraints in order:
       // 1. Reduce MinReputation to 0.3
       // 2. Increase MaxNodesPerASN to 3
       // 3. Remove geographic constraints
       // 4. Accept any available node with Reputation > 0.1
   }
   ```

**Selection Priority Formula**:

```
NodeScore = (1 / XORDistance) * ReputationWeight * DiversityBonus

Where:
- XORDistance = XOR(contentHash, nodeID) as uint256
- ReputationWeight = node.Reputation (0.0 - 1.0)
- DiversityBonus = 1.5 if unique ASN, 1.0 otherwise
```

**Example Selection**:

```go
// Content hash: 0xA3C4F2...
// Candidates after filtering:
// Node1: XOR=0x0012..., Reputation=0.95, ASN=AS12345, Region=US-EAST
// Node2: XOR=0x0089..., Reputation=0.88, ASN=AS12345, Region=US-EAST
// Node3: XOR=0x00AB..., Reputation=0.92, ASN=AS67890, Region=EU-WEST
// Node4: XOR=0x00CD..., Reputation=0.85, ASN=AS11111, Region=APAC

// Selected replicas (ReplicationFactor=3):
// 1. Node1 (closest, first in ASN=12345)
// 2. Node3 (next closest with different ASN)
// 3. Node4 (next closest with different ASN and region)
// Node2 skipped: would exceed MaxNodesPerASN for AS12345
```

### Peer Rating System

The peer rating system evaluates node reliability for content distribution decisions. Ratings affect peer selection priority for block downloads and replica placement.

**Rating Metrics**:

| Metric | Weight | Range | Description |
|--------|--------|-------|-------------|
| Bandwidth | 0.25 | 0.0-1.0 | Normalized transfer speed |
| Latency | 0.25 | 0.0-1.0 | Response time (inverted) |
| Uptime | 0.30 | 0.0-1.0 | Availability percentage |
| Transfer Success | 0.20 | 0.0-1.0 | Successful transfer ratio |

**Calculation Formula**:

```go
type PeerMetrics struct {
    BandwidthBps       uint64    // Measured bandwidth (bytes/sec)
    LatencyMs          uint32    // Average latency (milliseconds)
    UptimeSeconds      uint64    // Total uptime observed
    TotalAttempts      uint64    // Total transfer attempts
    SuccessfulTransfers uint64   // Successful transfers
    LastMeasured       time.Time // Last metric update
}

// Calculate peer rating (0.0 - 1.0)
func CalculatePeerRating(metrics PeerMetrics) float64 {
    const (
        BandwidthWeight = 0.25
        LatencyWeight   = 0.25
        UptimeWeight    = 0.30
        SuccessWeight   = 0.20

        // Normalization constants
        MaxBandwidthBps = 100_000_000  // 100 MB/s = 1.0
        MinLatencyMs    = 10           // 10ms = 1.0
        MaxLatencyMs    = 5000         // 5000ms = 0.0
        TargetUptimeSec = 86400 * 30   // 30 days = 1.0
    )

    // Bandwidth score: linear scale, capped at MaxBandwidth
    bandwidthScore := min(float64(metrics.BandwidthBps) / MaxBandwidthBps, 1.0)

    // Latency score: inverted scale (lower is better)
    latencyScore := 1.0 - min(float64(metrics.LatencyMs - MinLatencyMs) /
                              float64(MaxLatencyMs - MinLatencyMs), 1.0)

    // Uptime score: logarithmic scale approaching 1.0
    uptimeScore := min(float64(metrics.UptimeSeconds) / TargetUptimeSec, 1.0)

    // Transfer success ratio
    var successScore float64
    if metrics.TotalAttempts > 0 {
        successScore = float64(metrics.SuccessfulTransfers) / float64(metrics.TotalAttempts)
    }

    // Weighted combination
    rating := (bandwidthScore * BandwidthWeight) +
              (latencyScore * LatencyWeight) +
              (uptimeScore * UptimeWeight) +
              (successScore * SuccessWeight)

    return rating
}
```

**Rating Decay**:

Peer ratings decay over time to reflect current network conditions and penalize stale data:

```go
const (
    DecayHalfLife    = 7 * 24 * time.Hour  // Rating halves every 7 days without updates
    MinDecayedRating = 0.1                  // Floor value after decay
    RefreshInterval  = 1 * time.Hour        // Metric refresh frequency
)

// Apply time-based decay to rating
func ApplyDecay(rating float64, lastMeasured time.Time) float64 {
    elapsed := time.Since(lastMeasured)
    halfLives := float64(elapsed) / float64(DecayHalfLife)

    // Exponential decay: rating * (0.5 ^ halfLives)
    decayedRating := rating * math.Pow(0.5, halfLives)

    // Apply floor
    return max(decayedRating, MinDecayedRating)
}
```

**Rating Update Events**:

| Event | Rating Impact |
|-------|---------------|
| Successful block transfer | +0.01 to success ratio |
| Failed block transfer | -0.02 to success ratio |
| Timeout (no response) | -0.05 to success ratio, latency penalty |
| Bandwidth measurement | Update bandwidth metric |
| Heartbeat received | Update uptime metric |
| Connection refused | -0.10 to success ratio |

**Peer Selection Priority**:

Peers are selected for block downloads based on their rating combined with block availability:

```go
// Select best peer for downloading a specific block
func SelectPeerForBlock(swarm *Swarm, blockIndex uint32) *SwarmPeer {
    var bestPeer *SwarmPeer
    var bestScore float64

    for _, peer := range swarm.Peers {
        // Skip peers that don't have the block
        if !peer.HasBlock(blockIndex) {
            continue
        }

        // Calculate selection score
        // Higher rating = higher priority
        // Rarer blocks get bonus to encourage rarest-first distribution
        rarity := swarm.GetBlockRarity(blockIndex)
        rarityBonus := 1.0 + (float64(rarity) / float64(swarm.BlockCount))

        score := peer.Reputation * rarityBonus

        if score > bestScore {
            bestScore = score
            bestPeer = peer
        }
    }

    return bestPeer
}
```

### Replication Factor Configuration

The replication factor determines how many copies of each content block are stored across the DHT network.

**Default Configuration**:

```go
const (
    DefaultReplicationFactor = 3   // Standard replica count
    MinReplicationFactor     = 1   // Minimum (no redundancy)
    MaxReplicationFactor     = 7   // Maximum replica count
)

type ReplicationConfig struct {
    Factor           int     // Number of replicas per block
    PopularityBoost  bool    // Enable dynamic adjustment
    PopularityWindow time.Duration // Measurement window for popularity
}
```

**Static Replication**:

By default, content uses a fixed replication factor of 3:

```go
// Standard replication (factor = 3)
config := ReplicationConfig{
    Factor:          3,
    PopularityBoost: false,
}

// Each block stored on 3 nodes:
// - Primary: Closest node by XOR distance
// - Replica 1: Second closest (different ASN)
// - Replica 2: Third closest (different region preferred)
```

**Dynamic Replication Based on Popularity**:

For frequently accessed content, the replication factor can be dynamically increased:

```go
type PopularityMetrics struct {
    AccessCount    uint64        // Total accesses in window
    UniqueRequesters uint32      // Unique nodes requesting
    Window         time.Duration // Measurement window
}

// Calculate dynamic replication factor
func DynamicReplicationFactor(metrics PopularityMetrics, baseConfig ReplicationConfig) int {
    if !baseConfig.PopularityBoost {
        return baseConfig.Factor
    }

    // Thresholds for popularity tiers
    const (
        HighPopularityAccesses   = 1000  // Accesses per hour
        MediumPopularityAccesses = 100   // Accesses per hour
    )

    accessRate := float64(metrics.AccessCount) / metrics.Window.Hours()

    var factor int
    switch {
    case accessRate >= HighPopularityAccesses:
        // High popularity: max replication
        factor = MaxReplicationFactor  // 7 replicas
    case accessRate >= MediumPopularityAccesses:
        // Medium popularity: increased replication
        factor = baseConfig.Factor + 2  // 5 replicas
    default:
        // Normal: base replication
        factor = baseConfig.Factor  // 3 replicas
    }

    // Clamp to valid range
    return clamp(factor, MinReplicationFactor, MaxReplicationFactor)
}
```

**Replication Factor Guidelines**:

| Content Type | Recommended Factor | Rationale |
|--------------|-------------------|-----------|
| OS Images | 5-7 | Critical for network boot, high availability required |
| Software Updates | 3-5 | Important but can tolerate brief unavailability |
| Git Repositories | 3 | Standard redundancy, less time-critical |
| Temporary/Cache | 1-2 | Ephemeral data, can be regenerated |

**Replication Maintenance**:

The system periodically verifies replica health and creates new replicas when nodes become unavailable:

```go
type ReplicationMaintainer struct {
    CheckInterval    time.Duration  // How often to verify replicas (default: 1 hour)
    RepairDelay      time.Duration  // Wait before creating new replica (default: 5 minutes)
    MaxConcurrentOps int            // Parallel repair operations (default: 10)
}

// Maintenance loop pseudocode:
// 1. For each stored content block:
//    a. Query DHT for current replica locations
//    b. Verify each replica is accessible (ping/probe)
//    c. If replica count < target factor:
//       - Wait RepairDelay (node might return)
//       - Select new replica node using selection algorithm
//       - Copy block to new node
//    d. If replica count > target factor:
//       - Remove excess replicas from lowest-rated nodes
```

### DHT Storage Integration

Two-tier storage: local LRU cache with DHT fallback for distributed persistence.

```go
type CachedContentStore struct {
    dht   ContentStore        // DHT backend (persistent)
    cache *LocalContentStore  // LRU cache (fast)
}

type LocalContentStore struct {
    blocks  map[[32]byte]*cacheEntry
    lru     *list.List         // Least-recently-used tracking
    maxSize int                // Maximum cache entries
}
```

**Storage Operations**:

```go
// Store block (DHT + cache)
store := content.NewCachedContentStore(dhtBackend, 1000)
err := store.StoreBlock(block)  // Writes to DHT, caches locally

// Retrieve block (cache first, DHT fallback)
block, err := store.GetBlock(hash)
// 1. Check local cache (fast)
// 2. If miss, fetch from DHT
// 3. Cache result for future requests

// Statistics
stats := store.CacheStats()
fmt.Printf("Hit rate: %.2f%%\n", hitRate * 100)
```

**DHT Key Patterns**:

```
block:{sha256_hash}
manifest:{type}:{identifier}
```

**Key Generation**:

```go
// Block key
blockKey := content.BlockKey(hash)
// Returns: "block:a3c4f2..."

// OS image manifest key
osKey := content.OSImageKey("alpine", "3.18", "amd64", "")
// Returns: "manifest:os-image:alpine:3.18:amd64"

// Git repo manifest key
gitKey := content.GitRepoKey("foundation", "trusted-boot", "main")
// Returns: "manifest:git-repo:foundation:trusted-boot:main"

// Update manifest key
updateKey := content.UpdateKey("systemd", "254.3")
// Returns: "manifest:update:systemd:254.3"
```

**Implementation**: `pkg/content/store.go`

### FROST-Signed Manifests

Manifests use FROST (Flexible Round-Optimized Schnorr Threshold) signatures for distributed trust.

```go
type FROSTManifest struct {
    RootHash    [32]byte            // Merkle root
    TotalSize   uint64              // File size in bytes
    BlockCount  uint32              // Number of blocks
    BlockHashes [][32]byte          // All block hashes
    Metadata    interface{}         // Type-specific metadata
    Signature   []byte              // FROST threshold signature
    SignedBy    string              // Pool ID that signed
    SignedAt    int64               // Unix timestamp
}
```

**Signature Operations**:

```go
// Create manifest from blocks
manifest, err := content.NewManifest(blocks, metadata)

// Sign with FROST threshold signature
payload, err := manifest.SigningPayload()
signature := frostPool.Sign(payload)
manifest.Sign(signature, poolID)

// Verify signature
valid := manifest.Verify(signature, publicKey)
```

**Implementation**: `pkg/content/manifest.go`

### Content Types

**OS Images**:

```go
type OSImageMetadata struct {
    Distribution string            // "Alpine", "Ubuntu", "Fedora"
    Version      string            // "22.04", "3.18"
    Architecture string            // "amd64", "arm64"
    Variant      string            // "server", "minimal"
    BootType     string            // "UEFI", "BIOS"
    PCRValues    map[string]string // TPM PCR values
}
```

**Git Repositories**:

```go
type GitRepoMetadata struct {
    RepoName     string // Repository name
    Organization string // Foundation org
    Branch       string // Branch name
    CommitHash   string // Full commit SHA
    ApprovedBy   string // Pool ID
    ApprovedAt   int64  // Approval timestamp
}
```

**Software Updates**:

```go
type UpdateMetadata struct {
    PackageName string   // Package name
    Version     string   // New version
    PrevVersion string   // Previous version
    Urgency     string   // "critical", "high", "medium", "low"
    TargetOS    []string // Compatible OS list
    Changelog   string   // Change summary
}
```

---

## Network Boot System

**Source**: `pkg/boot/`

### iPXE Boot Chain

**Boot Sequence**:

```
1. UEFI Secure Boot
   |
2. iPXE (signed bootloader)
   |
3. Chainload boot.ipxe from DHT Gateway
   |
4. Download OS kernel + initramfs
   |
5. TPM Measured Boot (PCR extension)
   |
6. Boot Linux with root=dht:{manifest_hash}
```

**Boot Configuration**:

```go
type BootConfig struct {
    GatewayURL   string            // Boot server URL
    Distribution string            // "alpine", "ubuntu", "fedora"
    Version      string            // OS version
    Architecture string            // "amd64", "arm64"
    Variant      string            // "minimal", "server"
    ManifestHash [32]byte          // DHT manifest hash
    KernelArgs   map[string]string // Additional kernel params
    TPMMeasure   bool              // Enable TPM measurement
    Timeout      int               // Boot menu timeout (seconds)
}
```

**Script Generation**:

```go
generator := boot.NewScriptGenerator("https://boot.example.com")
script, err := generator.Generate(config)
```

**Generated iPXE Script**:

```ipxe
#!ipxe
# Trusted DHT Network Boot Script
# Distribution: alpine 3.18
# Architecture: amd64

set gateway https://boot.example.com
set manifest a3c4f2e8d9b1c0a7f6e5d4c3b2a1098765432100fedcba9876543210abcdef
set distro alpine
set version 3.18
set arch amd64

# Download and verify kernel
kernel ${gateway}/os/${distro}/${version}/${arch}/vmlinuz
initrd ${gateway}/os/${distro}/${version}/${arch}/initramfs.img

# Boot parameters
imgargs vmlinuz root=dht:${manifest} ro quiet tpm=measure

boot
```

**Implementation**: `pkg/boot/ipxe.go`

### UEFI Secure Boot

- Boot loader signature verification
- Trusted key database (db, dbx, KEK, PK)
- Prevents unsigned code execution

### TPM Measured Boot Chain

**PCR (Platform Configuration Register) Values**:

| PCR | Purpose | Measurement |
|-----|---------|-------------|
| 0   | UEFI firmware | Firmware code and configuration |
| 1   | UEFI configuration | Platform configuration |
| 2   | Option ROM code | PCI expansion ROM code |
| 4   | Boot loader code | iPXE bootloader |
| 7   | Secure Boot state | Secure Boot policy |
| 8   | Kernel command line | Boot parameters |
| 9   | Kernel and initramfs | OS kernel and initial RAM filesystem |
| 14  | MokList / Updates | Machine Owner Keys / Update history |

**Measured Boot Chain**:

```
Firmware -> iPXE -> Boot Script -> Kernel -> Initramfs -> Root FS
   PCR0     PCR4      PCR8        PCR9       PCR9      PCR14
```

Each stage measures the next before executing.

**TPM Configuration**:

```go
type TPMConfig struct {
    DevicePath   string  // "/dev/tpm0" or "simulator"
    PCRPolicy    []int   // PCRs to seal keys to
    KeyAlgorithm string  // "rsa2048", "ecc256", "ecc384"
}

// Initialize TPM
tpm, err := boot.NewTPM(TPMConfig{
    DevicePath:   "/dev/tpm0",
    PCRPolicy:    []int{0, 1, 2, 4, 7, 8, 9, 14},
    KeyAlgorithm: boot.AlgorithmECC256,
})
```

**PCR Extension**:

```go
// Extend PCR with measurement
data := computeMeasurement(kernel)
err := tpm.ExtendPCR(9, data)  // PCR 9 = kernel + initramfs

// PCR extension formula:
// PCR_new = SHA256(PCR_old || SHA256(data))
```

**Key Sealing**:

```go
// Seal encryption key to current PCR values
encryptionKey := generateKey()
sealed, err := tpm.SealKey(encryptionKey, []int{0, 2, 7, 9})

// Unseal (only succeeds if PCRs unchanged)
key, err := tpm.UnsealKey(sealed)
// Returns error if system configuration changed
```

**Attestation**:

```go
// Create attestation quote
nonce := generateNonce() // 32 bytes
quote, err := tpm.CreateAttestationQuote(nonce)

// Quote structure:
// [magic][pcr_count][pcr_index:pcr_value]...[nonce][signature]

// Remote verification
valid := verifyQuote(quote, expectedPCRs, publicKey)
```

**Implementation**: `pkg/boot/tpm.go`

### Boot Verification

**Supported Distributions**:

| Distribution | Versions | Variants | Use Case |
|--------------|----------|----------|----------|
| Alpine Linux | 3.17, 3.18, 3.19 | minimal, standard | Lightweight, fast boot |
| Ubuntu | 20.04, 22.04, 24.04 | server, desktop | Full-featured enterprise |
| Fedora | 38, 39, 40 | server, workstation | Cutting-edge features |

**Boot Menu Generation**:

```go
configs := []boot.BootConfig{
    {Distribution: "alpine", Version: "3.18", Architecture: "amd64", Variant: "minimal"},
    {Distribution: "ubuntu", Version: "22.04", Architecture: "amd64", Variant: "server"},
    {Distribution: "fedora", Version: "39", Architecture: "amd64", Variant: "server"},
}

menu, err := generator.GenerateMenu(configs)
```

**Initramfs Structure**:

```
initramfs/
+-- init                    # Init script (DHT mount)
+-- bin/
|   +-- busybox            # Core utilities
|   +-- dht-client         # DHT block fetcher
+-- lib/
|   +-- modules/           # Kernel modules (network, TPM)
+-- etc/
    +-- dht.conf           # DHT configuration
```

**Boot Server API**:

```
GET  /boot.ipxe                              # Main boot script
GET  /boot/menu.ipxe                         # Boot menu
GET  /os/{distro}/{version}/{arch}/vmlinuz   # Kernel binary
GET  /os/{distro}/{version}/{arch}/initramfs.img  # Initial RAM filesystem
GET  /manifest/{distro}/{version}/{arch}     # OS manifest (JSON)
GET  /health                                 # Health check
```

**Implementation**: `pkg/boot/server.go`, `pkg/boot/provision.go`

---

## Update System

**Source**: `pkg/updates/`

### Atomic Updates with Rollback

**Update Manifest Structure**:

```go
type UpdateManifest struct {
    Manifest     *content.FROSTManifest  // FROST-signed manifest
    PackageName  string                  // Package being updated
    Version      string                  // Target version
    PrevVersion  string                  // Previous version
    Urgency      string                  // "critical", "security", "normal", "low"
    VerifiedAt   time.Time               // Signature verification time
}
```

**Installation Process**:

```go
type Installer struct {
    installRoot string
    backupRoot  string
    registry    *InstalledRegistry
}

installer := updates.NewInstaller("/usr", "/var/backup")
installed, err := installer.Install(ctx, manifest)
```

**Atomic Installation Steps**:

1. **Backup Current Version**
   ```go
   backupPath := filepath.Join(backupRoot, packageName, prevVersion)
   err := copyDir(currentPath, backupPath)
   ```

2. **Extract to Temporary Location**
   ```go
   tempPath := filepath.Join(tempRoot, packageName, version)
   err := extractBlocks(manifest.Manifest, tempPath)
   ```

3. **Verify All Files**
   ```go
   for file, expectedHash := range manifest.FileHashes {
       actualHash := sha256sum(file)
       if actualHash != expectedHash {
           return ErrHashMismatch
       }
   }
   ```

4. **Atomic Swap**
   ```go
   err := os.Rename(tempPath, installPath)
   // Atomic filesystem operation
   ```

5. **Update Registry**
   ```go
   registry.Register(installed)
   ```

**Rollback Support**:

```go
// Rollback to previous version
err := installer.Rollback(ctx, packageName)

// Steps:
// 1. Verify backup exists
// 2. Stop services using package
// 3. Atomic swap: current -> temp, backup -> current
// 4. Restart services
// 5. Update registry
// 6. Delete temp

// Get rollback info
rollback, exists := installer.GetRollbackInfo(packageName)
if exists {
    fmt.Printf("Can rollback to: %s\n", rollback.PrevVersion)
}
```

**Implementation**: `pkg/updates/installer.go`

### FROST-Signed Manifests

**Creating Update Manifest**:

```go
// Chunk update package
file, _ := os.Open("/path/to/update.tar.gz")
blocks, err := content.ChunkFile(file, content.ContentTypeUpdate, nil)

// Create update manifest
manifest, err := updates.NewUpdateManifest(
    "systemd",              // package
    "254.3",                // version
    blocks,                 // content blocks
    "Security fixes",       // changelog
    []string{"linux"},      // targetOS
    updates.UrgencySecurity,
)

// Sign with FROST
payload, _ := manifest.Manifest.SigningPayload()
signature := frostPool.Sign(payload)
manifest.Manifest.Sign(signature, poolID)
```

**Manifest Validation**:

```go
// Validate manifest integrity
err := manifest.Validate()
// Checks:
// - FROST manifest integrity
// - Version format (semver)
// - Urgency level validity
// - Block hash consistency

// Check compatibility
compatible := manifest.IsCompatible("254.2")  // current version
```

**Implementation**: `pkg/updates/manifest.go`

### Update Channels

```go
type Channel struct {
    Name        string    // "stable", "beta", "nightly"
    Priority    int       // Channel priority
    Packages    []string  // Subscribed packages
    AutoUpdate  bool      // Automatic installation
    CheckInterval time.Duration  // Check frequency
}

// Create channel manager
manager := updates.NewChannelManager(store)

// Subscribe to channel
channel := &updates.Channel{
    Name:          "stable",
    Priority:      10,
    Packages:      []string{"systemd", "kernel", "openssh"},
    AutoUpdate:    false,
    CheckInterval: 1 * time.Hour,
}

err := manager.Subscribe(channel)

// Check for updates
available, err := manager.CheckUpdates(ctx)
```

**Urgency Levels**:

```go
const (
    UrgencyCritical Urgency = "critical"  // Immediate installation
    UrgencySecurity Urgency = "security"  // Security-related
    UrgencyNormal   Urgency = "normal"    // Regular updates
    UrgencyLow      Urgency = "low"       // Optional updates
)
```

**Implementation**: `pkg/updates/channel.go`

### Update Distribution Flow

**P2P Swarm Download**:

```go
type Downloader struct {
    store   content.ContentStore
    swarm   *content.Swarm
    maxPeers int
}

downloader := updates.NewDownloader(store, 50) // max 50 peers

// Download update via swarm
progress := make(chan updates.DownloadProgress)
err := downloader.Download(ctx, manifest, progress)

// Monitor progress
for p := range progress {
    fmt.Printf("Downloaded: %d/%d blocks (%.1f%%)\n",
        p.DownloadedBlocks,
        p.TotalBlocks,
        float64(p.DownloadedBlocks)/float64(p.TotalBlocks)*100)
}
```

**Progress Tracking**:

```go
type DownloadProgress struct {
    PackageName      string
    Version          string
    TotalBlocks      uint32
    DownloadedBlocks uint32
    TotalSize        uint64
    DownloadedSize   uint64
    StartedAt        time.Time
    Status           UpdateStatus
    Error            string
}

// Status transitions:
// Pending -> Downloading -> Verifying -> Installing -> Installed
```

**TPM PCR Extension for Updates**:

```go
// Measure update before installation
measurement := computeUpdateMeasurement(manifest)
err = tpm.ExtendPCR(14, measurement)

// PCR 14 provides tamper-proof update history:
// PCR14 = SHA256(PCR14_old || SHA256("systemd:254.3:hash:timestamp"))
```

**Implementation**: `pkg/updates/downloader.go`

### Complete Update Workflow

```go
// 1. Subscribe to channel
manager := updates.NewChannelManager(store)
manager.Subscribe(&updates.Channel{
    Name:          "stable",
    Packages:      []string{"systemd"},
    CheckInterval: 1 * time.Hour,
})

// 2. Check for updates
available, err := manager.CheckUpdates(ctx)
update := available[0]

// 3. Download via P2P swarm
downloader := updates.NewDownloader(store, 50)
manifest, err := downloader.Download(ctx, update, progress)

// 4. Verify manifest
err = manifest.Validate()

// 5. Measure update (TPM)
tpm.ExtendPCR(14, computeUpdateMeasurement(manifest))

// 6. Install atomically
installer := updates.NewInstaller("/usr", "/var/backup")
installed, err := installer.Install(ctx, manifest)

// 7. Rollback on failure
if err != nil {
    installer.Rollback(ctx, update.PackageName)
}

// 8. Create attestation quote
quote, err := tpm.CreateAttestationQuote(nonce)
```

---

## Git Repository System

**Source**: `pkg/git/`

### Foundation-Approved Storage

All repositories must be approved by the foundation before DHT storage:

- **Purpose**: Prevent DHT pollution with unauthorized content
- **Approval Process**: 3-of-5 foundation committee members
- **Scope**: Organization, repository, and branch must be approved
- **Duration**: Approvals have configurable timeout (default 30 days)

**Supported Repository Types**:

```go
// Only foundation-managed repositories
- Operating system builds
- Network boot images
- Core system packages
- Security tools
- Foundation documentation

// Not supported (external hosting)
- Personal projects
- Third-party software
- Experimental code
- Non-critical tools
```

### 3-of-5 Approval Workflow

**Approval Configuration**:

```go
type ApprovalConfig struct {
    RequiredApprovers int           // Minimum approvals (default: 3)
    ApprovalTimeout   time.Duration // Approval validity (default: 30 days)
}

config := git.ApprovalConfig{
    RequiredApprovers: 3,
    ApprovalTimeout:   30 * 24 * time.Hour,
}

manager := git.NewApprovalManager(config)
```

**Submitting Repository for Approval**:

```go
request, err := manager.SubmitRequest(
    "foundation",          // organization
    "trusted-boot",        // repository
    "main",                // branch
    "a3c4f2e8d9b1c0a7...", // commit hash
    "alice@foundation.org", // submitter
)

type ApprovalRequest struct {
    RequestID    [32]byte
    Organization string
    RepoName     string
    Branch       string
    CommitHash   string
    Submitter    string
    SubmittedAt  time.Time
    Approvals    []Approval
    Status       ApprovalStatus  // "pending", "approved", "rejected"
}
```

**Voting Process**:

```go
approval := git.Approval{
    ApproverID: "alice@foundation.org",
    Approved:   true,
    Timestamp:  time.Now(),
    Signature:  signApproval(requestID, true, privateKey),
    Comment:    "Security audit passed",
}

err = manager.AddApproval(request.RequestID, approval)
```

**Approval States**:

```go
const (
    StatusPending  ApprovalStatus = "pending"   // Awaiting votes
    StatusApproved ApprovalStatus = "approved"  // 3+ approvals received
    StatusRejected ApprovalStatus = "rejected"  // Any rejection or timeout
)

// Automatic state transitions:
// 1. Submit -> StatusPending
// 2. Receive 3 approvals -> StatusApproved
// 3. Receive 1 rejection -> StatusRejected
// 4. Timeout expires -> StatusRejected
```

**Implementation**: `pkg/git/approval.go`

### Git Bundle Handling

**Bundle Structure**:

```go
type Bundle struct {
    Data        []byte            // Git bundle binary data
    Refs        map[string]string // Reference -> commit hash mapping
    Objects     int               // Number of Git objects
    Size        int64             // Uncompressed size
    CommitHash  string            // HEAD commit hash
    CreatedAt   time.Time         // Bundle creation time
    Compression string            // "gzip", "zstd", "none"
}

type BundleConfig struct {
    BlockSize   int     // Chunk size (default 1MB)
    Compression string  // Compression algorithm
}
```

**Creating Git Bundle**:

```go
config := git.DefaultBundleConfig()
// config.BlockSize = 1MB
// config.Compression = "gzip"

// Create full bundle
creator := git.NewBundleCreator(config)
bundle, err := creator.CreateBundle("/path/to/repo", []string{
    "heads/main",
    "heads/develop",
})

// Create incremental bundle
incrementalBundle, err := creator.CreateIncrementalBundle(
    "/path/to/repo",
    "abc123", // Since this commit
)
```

**Compression Options**:

| Algorithm | Compression Ratio | CPU Usage | Use Case |
|-----------|------------------|-----------|----------|
| gzip | ~50% | Moderate | Default, widely supported |
| zstd | ~60% | Lower | Better compression, faster decompression |
| none | 0% | None | Pre-compressed data |

**Implementation**: `pkg/git/bundle.go`

### Bundle Chunking for DHT

**Chunking for Storage**:

```go
// Split bundle into 1MB chunks
blockSize := 1024 * 1024 // 1MB
chunks, err := git.ChunkBundle(bundle, blockSize)

// Store each chunk in DHT
for i, chunk := range chunks {
    key := fmt.Sprintf("bundle-%s-chunk-%d", bundle.CommitHash, i)
    dht.Store(key, chunk)
}

// Store metadata separately
metadata, _ := bundle.MarshalMetadata()
dht.Store(fmt.Sprintf("bundle-%s-metadata", bundle.CommitHash), metadata)
```

**Retrieving from DHT**:

```go
// Retrieve metadata
metadataBytes, _ := dht.Get("bundle-abc123-metadata")
metadata, _ := git.UnmarshalMetadata(metadataBytes)

// Retrieve all chunks
numChunks := (metadata.Size + blockSize - 1) / blockSize
chunks := make([][]byte, numChunks)
for i := 0; i < numChunks; i++ {
    key := fmt.Sprintf("bundle-%s-chunk-%d", metadata.CommitHash, i)
    chunks[i], _ = dht.Get(key)
}

// Reassemble bundle
bundle, _ := git.ReassembleBundle(chunks)

// Verify integrity
reader := git.NewBundleReader()
err := reader.VerifyBundle(bundle)
```

**Git Remote Helper Protocol**:

```bash
# Clone from DHT
git clone dht://foundation/trusted-boot

# Fetch updates
git fetch dht://foundation/trusted-boot

# Push (requires approval first)
git push dht://foundation/trusted-boot main
```

**Remote Helper Implementation**:

```go
type RemoteHelper struct {
    store    content.ContentStore
    approval *ApprovalManager
    registry *RepositoryRegistry
}

// Push implementation
func (h *RemoteHelper) Push(src, dst string) error {
    // 1. Create bundle
    bundle, err := git.CreateBundle(repo, src, config)

    // 2. Check approval
    approved := h.approval.IsApproved(org, repo, branch)
    if !approved {
        request, err := h.approval.SubmitRequest(org, repo, branch, commit, submitter)
        return ErrApprovalRequired{RequestID: request.RequestID}
    }

    // 3. Chunk bundle for DHT
    blocks, err := content.ChunkFile(bytes.NewReader(bundle.Data),
        content.ContentTypeGitRepo, nil)

    // 4. Create manifest and store
    manifest, err := content.NewManifest(blocks, metadata)
    for _, block := range blocks {
        h.store.StoreBlock(block)
    }

    key := content.GitRepoKey(org, repo, branch)
    h.store.StoreManifest(key, manifest)

    return nil
}
```

**Implementation**: `pkg/git/remote.go`

### Repository Registry

```go
type RepositoryRegistry struct {
    repos    map[string]*RepositoryEntry
    mu       sync.RWMutex
}

type RepositoryEntry struct {
    Organization string
    RepoName     string
    Branch       string
    CommitHash   string
    ManifestHash [32]byte
    BundleSize   int64
    ApprovedBy   []string  // Approver IDs
    ApprovedAt   time.Time
    UpdatedAt    time.Time
}

// Register approved repository
registry := git.NewRepositoryRegistry()
err := registry.Register(&git.RepositoryEntry{
    Organization: "foundation",
    RepoName:     "trusted-boot",
    Branch:       "main",
    CommitHash:   "a3c4f2e8...",
    ManifestHash: manifestHash,
    BundleSize:   15728640,  // 15 MB
    ApprovedBy:   []string{"alice", "bob", "carol"},
})

// Lookup repository
entry, exists := registry.Get("foundation", "trusted-boot", "main")
```

**Implementation**: `pkg/git/approval_registry.go`

### Validation Rules

**Organization Names**:
- Length: 1-100 characters
- Pattern: `[a-zA-Z0-9_-]+`

**Repository Names**:
- Length: 1-100 characters
- Pattern: `[a-zA-Z0-9_-]+`

**Branch Names**:
- Length: 1-255 characters
- Pattern: `[a-zA-Z0-9/_-]+`

---

## Security Considerations

### Content Storage Security

- **SHA-256 hashing**: Each block cryptographically verified
- **Merkle trees**: Efficient partial verification
- **FROST signatures**: Threshold signatures prevent single-point compromise

### Network Boot Security

- **UEFI Secure Boot**: Prevents unsigned code execution
- **TPM measured boot**: Cryptographic chain of trust
- **Key sealing**: Encryption keys bound to system state

### Update Security

- **Atomic operations**: No partial installations
- **Rollback support**: Recovery from failed updates
- **TPM audit trail**: Tamper-proof update history

### Git Repository Security

- **Multi-signature**: 3-of-5 prevents single compromised approver
- **Signed approvals**: Each vote cryptographically signed
- **Timeout enforcement**: Stale approvals automatically rejected
- **Audit trail**: All approvals permanently recorded

---

## Error Handling

All subsystems use typed errors for precise handling:

**Content Storage**:

```go
ErrInvalidBlock{Hash: hash, Reason: "hash mismatch"}
ErrBlockNotFound{Hash: hash}
ErrInvalidManifest{Key: key, Reason: reason}
ErrManifestNotFound{Key: key}
ErrEmptyMerkleBlocks{}
ErrMerkleProofInvalid{}
```

**Network Boot**:

```go
ErrInvalidDistribution{Distribution: distro}
ErrInvalidArchitecture{Architecture: arch}
ErrInvalidVersion{Version: version}
ErrMissingManifest{}
ErrTPMNotAvailable{}
ErrTPMKeyGeneration{Err: err}
```

**Update System**:

```go
ErrInvalidPackageName{PackageName: name}
ErrInvalidVersion{}
ErrDownloadFailed{PackageName: pkg, Reason: reason}
ErrInstallFailed{PackageName: pkg, Reason: reason}
ErrRollbackFailed{PackageName: pkg, Reason: reason}
ErrNoBackupAvailable{PackageName: pkg}
```

**Git Repository**:

```go
ErrInvalidRepoName{Name: name, Reason: reason}
ErrInvalidOrganization{Name: org, Reason: reason}
ErrInvalidBranch{Name: branch, Reason: reason}
ErrRequestNotFound{RequestID: id}
ErrApproverAlreadyVoted{RequestID: id, ApproverID: approver}
ErrRequestExpired{RequestID: id, SubmittedAt: time}
ErrBundleInvalid{Reason: reason}
```

---

## Performance Characteristics

### Content Storage

| Metric | Value |
|--------|-------|
| Block Size | 1MB (optimal for network transfer) |
| Hash Algorithm | SHA-256 (32 bytes per hash) |
| Cache Size | Configurable (default 1000 blocks = ~1GB) |
| LRU Eviction | O(1) using doubly-linked list |
| Merkle Proof Size | O(log n) where n = block count |
| Swarm Peer Selection | O(p) where p = peer count |

### Network Boot

| Metric | Value |
|--------|-------|
| Boot Time | ~30 seconds (Alpine minimal) |
| Kernel Size | 5-15 MB (compressed) |
| Initramfs Size | 10-50 MB |
| Network Bandwidth | 1-5 MB/s download |
| TPM Operations | ~100ms per PCR extend |

### Update System

| Metric | Value |
|--------|-------|
| Download Speed | 5-50 MB/s (P2P swarm) |
| Verification Time | ~100ms per manifest |
| Installation Time | 1-30 seconds (package dependent) |
| Rollback Time | 1-10 seconds (atomic swap) |
| Manifest Size | 2-10 KB (typical) |

### Git Repository

| Metric | Value |
|--------|-------|
| Bundle Creation | 1-10 seconds (repo size dependent) |
| Bundle Size | 10-500 MB (typical repositories) |
| Approval Process | Minutes to hours (human voting) |
| Clone Speed | 5-50 MB/s (P2P swarm) |
| Fetch Speed | 1-20 MB/s (incremental updates) |
| Registry Lookup | <10ms |

---

## Related Components

- **DHT Core**: Key-value storage (`pkg/dht/`)
- **FROST Signatures**: Threshold signatures (`pkg/frost/`)
- **OS Image Builder**: Creates bootable OS images (`pkg/osimage/`)
