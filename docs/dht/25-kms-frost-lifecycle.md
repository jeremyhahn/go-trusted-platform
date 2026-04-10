# KMS Integration for FROST Share Management

## Overview

The Key Management Service (KMS) provides secure, hierarchical storage for FROST threshold signature shares within the go-trusted-platform. This document specifies the integration between KMS backends and FROST share lifecycle operations, ensuring cryptographic material remains protected at rest, in transit, and during use.

> **Cross-Reference:** See [04-cryptographic-protocols.md](04-cryptographic-protocols.md) for FROST protocol details and [11-operations.md](11-operations.md) for backup and recovery procedures.

---

## KMS-FROST Relationship

### Architectural Overview

```
+------------------------------------------------------------------+
|                        KMS Backend Layer                          |
+------------------------------------------------------------------+
|                                                                    |
|   +------------+    +-------------+    +-------------+            |
|   |   TPM 2.0  |    |  PKCS#11    |    | Cloud KMS   |            |
|   |  Backend   |    |  HSM        |    | (AWS/GCP)   |            |
|   +-----+------+    +------+------+    +------+------+            |
|         |                  |                  |                    |
|         v                  v                  v                    |
|   +--------------------------------------------------+            |
|   |            Unified KMS Interface                  |            |
|   |  - CreateKey()    - Encrypt()    - Seal()        |            |
|   |  - ImportKey()    - Decrypt()    - Unseal()      |            |
|   |  - ExportKey()    - Sign()       - Attest()      |            |
|   +--------------------------------------------------+            |
|                              |                                     |
+------------------------------+-------------------------------------+
                               |
                               v
+------------------------------------------------------------------+
|                   FROST Share Manager                             |
+------------------------------------------------------------------+
|                                                                    |
|   +---------------+    +---------------+    +------------------+  |
|   | Share Storage |    | Share Refresh |    | Share Recovery   |  |
|   | & Encryption  |    | Coordinator   |    | Service          |  |
|   +---------------+    +---------------+    +------------------+  |
|                                                                    |
+------------------------------------------------------------------+
```

### Core Principles

| Principle | Description | Implementation |
|-----------|-------------|----------------|
| **Defense in Depth** | Multiple encryption layers | DEK encrypted by KEK, KEK in KMS |
| **Key Hierarchy** | Separation of concerns | Master -> KEK -> DEK -> Share |
| **Hardware Binding** | TPM for identity shares | PCR-bound sealing policy |
| **Multi-Backend** | Flexibility and redundancy | TPM, HSM, Cloud KMS support |
| **Auditability** | Complete lifecycle tracking | Immutable audit log |

### Multi-Backend Support

The KMS abstraction layer supports multiple backend types, allowing operators to select the appropriate security level for their deployment:

```go
// KMSBackendType identifies the storage backend
type KMSBackendType uint8

const (
    // KMSBackendTPM provides hardware-bound storage via TPM 2.0
    // Recommended for: Identity shares, coordinator nodes
    KMSBackendTPM KMSBackendType = iota

    // KMSBackendPKCS11 provides HSM-backed storage via PKCS#11
    // Recommended for: High-security deployments, enterprise environments
    KMSBackendPKCS11

    // KMSBackendAWSKMS provides cloud-native storage via AWS KMS
    // Recommended for: Cloud deployments, multi-region setups
    KMSBackendAWSKMS

    // KMSBackendGCPKMS provides cloud-native storage via GCP Cloud KMS
    // Recommended for: GCP-native deployments
    KMSBackendGCPKMS

    // KMSBackendSoftware provides software-based storage (development only)
    // NOT RECOMMENDED for production
    KMSBackendSoftware
)

// KMSConfig configures the KMS backend for FROST share storage
type KMSConfig struct {
    // Primary backend for share storage
    PrimaryBackend    KMSBackendType

    // Secondary backend for redundant storage
    SecondaryBackend  KMSBackendType

    // Backend-specific configuration
    TPMConfig         *TPMBackendConfig
    PKCS11Config      *PKCS11BackendConfig
    AWSKMSConfig      *AWSKMSBackendConfig
    GCPKMSConfig      *GCPKMSBackendConfig

    // Share lifecycle settings
    RotationPolicy    ShareRotationPolicy
    BackupPolicy      ShareBackupPolicy
    AuditConfig       ShareAuditConfig
}
```

---

## Share Storage Format

### FROST Share Structure

Each FROST share is stored with comprehensive metadata for lifecycle management:

```go
// FROSTShareRecord represents a stored FROST share with full metadata
type FROSTShareRecord struct {
    // Identity
    ShareID        [32]byte       // Unique identifier: SHA-256(GroupID || ShareIndex || Version)
    GroupID        [32]byte       // Identifier of the FROST group (CA pool)
    ShareIndex     uint16         // Participant index (1 to n)
    Version        uint32         // Share version (incremented on rotation)

    // Cryptographic Material (encrypted)
    SecretShare    EncryptedBlob  // f(index) - the participant's secret share
    PublicCommitment []byte       // g^share - public verification point

    // Metadata
    Metadata       ShareMetadata

    // Storage
    StorageBackend KMSBackendType
    KeyReference   string         // Reference to encryption key in KMS
}

// ShareMetadata contains lifecycle and audit information
type ShareMetadata struct {
    // Timestamps
    CreatedAt      time.Time      // When share was generated
    RotatedAt      time.Time      // Last rotation timestamp
    ExpiresAt      time.Time      // Share expiration (triggers rotation)
    LastAccessedAt time.Time      // Last use timestamp

    // Provenance
    DKGSessionID   [32]byte       // DKG session that created this share
    DKGRound       uint64         // DKG round number
    ParticipantCount uint16       // Total participants (n)
    Threshold      uint16         // Required threshold (t)

    // Audit
    AccessCount    uint64         // Number of times accessed
    SignatureCount uint64         // Number of signatures produced
    AuditHash      [32]byte       // Hash of audit log entries

    // Status
    Status         ShareStatus
    RevokedAt      time.Time      // If revoked, when
    RevocationReason string       // If revoked, why
}

// ShareStatus indicates the current state of a share
type ShareStatus uint8

const (
    ShareStatusActive    ShareStatus = iota // Share is valid and usable
    ShareStatusRotating                     // Share is being rotated (old still valid)
    ShareStatusExpired                      // Share has expired, rotation required
    ShareStatusRevoked                      // Share has been revoked
    ShareStatusRecovering                   // Share is being recovered from backup
)
```

### Encryption Envelope

FROST shares are encrypted using a layered envelope encryption scheme:

```go
// EncryptedBlob contains the encrypted share with envelope metadata
type EncryptedBlob struct {
    // Encryption parameters
    Algorithm      string         // "AES-256-GCM" (required)
    KeyID          string         // Reference to DEK in KMS
    IV             [12]byte       // Unique initialization vector
    AuthTag        [16]byte       // GCM authentication tag

    // Encrypted data
    Ciphertext     []byte         // Encrypted share bytes

    // Key derivation (for rotation)
    KeyVersion     uint32         // DEK version
    KDFSalt        [32]byte       // Salt for key derivation
}

// ShareEncryptionEnvelope provides the full encryption context
type ShareEncryptionEnvelope struct {
    // Data Encryption Key (DEK) - encrypts the share
    DEK            DEKRecord

    // Key Encryption Key (KEK) - encrypts the DEK
    KEK            KEKReference

    // Encrypted share
    EncryptedShare EncryptedBlob

    // Integrity
    EnvelopeMAC    [32]byte       // HMAC-SHA-256 of entire envelope
}

// DEKRecord tracks the data encryption key
type DEKRecord struct {
    KeyID          string         // Unique identifier
    Algorithm      string         // "AES-256"
    CreatedAt      time.Time
    ExpiresAt      time.Time
    EncryptedKey   []byte         // DEK encrypted by KEK
    KeyVersion     uint32
}

// KEKReference points to the key encryption key in KMS
type KEKReference struct {
    Backend        KMSBackendType
    KeyHandle      string         // Backend-specific key handle
    KeyVersion     uint32
    KeyPolicy      string         // Access policy (e.g., PCR policy for TPM)
}
```

### TPM Sealing for Identity Shares

Identity shares (node IDevID-related) receive additional protection through TPM sealing:

```go
// TPMSealedShare provides hardware-bound share protection
type TPMSealedShare struct {
    // Sealed blob
    SealedBlob     []byte         // TPM2B_PRIVATE + TPM2B_PUBLIC

    // Sealing context
    ParentHandle   uint32         // TPM parent key handle (SRK)
    PCRSelection   PCRSelection   // PCRs bound to unsealing

    // Policy
    PolicyDigest   [32]byte       // TPM policy session digest
    PolicyScript   []byte         // Serialized policy commands

    // Metadata
    SealedAt       time.Time
    TPMVendor      string         // TPM manufacturer
    TPMFirmware    string         // TPM firmware version
}

// PCRSelection defines which PCRs are bound to the share
type PCRSelection struct {
    // PCR bank selection (SHA-256 recommended)
    HashAlgorithm  uint16         // TPM_ALG_SHA256 = 0x000B

    // Selected PCR indices
    // Recommended: 0 (BIOS), 2 (Option ROMs), 7 (SecureBoot)
    PCRIndices     []int

    // Expected PCR values at seal time
    ExpectedValues map[int][32]byte
}

// PCR indices for different share types
const (
    // PCRBootChain binds to BIOS and boot configuration
    PCRBootChain = 0

    // PCROptionROMs binds to option ROM measurements
    PCROptionROMs = 2

    // PCRSecureBoot binds to Secure Boot policy
    PCRSecureBoot = 7

    // PCRKernel binds to kernel and initramfs
    PCRKernel = 8

    // PCRApplications binds to application measurements
    PCRApplications = 9
)

// DefaultIdentitySharePCRPolicy returns the recommended PCR binding
// for identity-critical FROST shares
func DefaultIdentitySharePCRPolicy() PCRSelection {
    return PCRSelection{
        HashAlgorithm: 0x000B, // SHA-256
        PCRIndices:    []int{0, 2, 7},
    }
}
```

---

## Key Lifecycle Operations

### Generation: Initial DKG Share Storage

When DKG completes, shares are immediately encrypted and stored in KMS:

```go
// ShareGenerator handles secure storage of newly generated shares
type ShareGenerator struct {
    kms           KMSBackend
    auditLog      AuditLogger
    pcrPolicy     PCRSelection
}

// StoreNewShare securely stores a share from completed DKG
func (sg *ShareGenerator) StoreNewShare(
    ctx context.Context,
    share *DKGShare,
    groupID [32]byte,
    dkgSession *DKGSessionInfo,
) (*FROSTShareRecord, error) {
    // Step 1: Generate unique share ID
    shareID := sg.computeShareID(groupID, share.Index, 1)

    // Step 2: Generate fresh DEK for this share
    dek, err := sg.kms.GenerateDataKey(ctx, "AES-256")
    if err != nil {
        return nil, ErrDEKGenerationFailed{Cause: err}
    }

    // Step 3: Encrypt share with DEK
    encryptedShare, err := sg.encryptShare(share.Value, dek)
    if err != nil {
        return nil, ErrShareEncryptionFailed{Cause: err}
    }

    // Step 4: Encrypt DEK with KEK (stored in KMS)
    kekRef, err := sg.kms.GetOrCreateKEK(ctx, groupID)
    if err != nil {
        return nil, ErrKEKAccessFailed{Cause: err}
    }

    encryptedDEK, err := sg.kms.EncryptWithKEK(ctx, kekRef, dek.Key)
    if err != nil {
        return nil, ErrDEKEncryptionFailed{Cause: err}
    }

    // Step 5: For identity shares, also seal to TPM
    var tpmSealed *TPMSealedShare
    if sg.isIdentityShare(groupID) {
        tpmSealed, err = sg.sealToTPM(ctx, share.Value, sg.pcrPolicy)
        if err != nil {
            return nil, ErrTPMSealingFailed{Cause: err}
        }
    }

    // Step 6: Create share record
    record := &FROSTShareRecord{
        ShareID:          shareID,
        GroupID:          groupID,
        ShareIndex:       share.Index,
        Version:          1,
        SecretShare:      encryptedShare,
        PublicCommitment: share.PublicCommitment,
        Metadata: ShareMetadata{
            CreatedAt:        time.Now(),
            ExpiresAt:        time.Now().Add(90 * 24 * time.Hour),
            DKGSessionID:     dkgSession.SessionID,
            DKGRound:         dkgSession.Round,
            ParticipantCount: dkgSession.N,
            Threshold:        dkgSession.T,
            Status:           ShareStatusActive,
        },
        StorageBackend: sg.kms.BackendType(),
        KeyReference:   kekRef.KeyHandle,
    }

    // Step 7: Persist to KMS
    if err := sg.kms.StoreShareRecord(ctx, record, encryptedDEK, tpmSealed); err != nil {
        return nil, ErrShareStorageFailed{Cause: err}
    }

    // Step 8: Audit log
    sg.auditLog.LogShareCreation(ctx, shareID, groupID, share.Index)

    return record, nil
}

// encryptShare encrypts the share value with AES-256-GCM
func (sg *ShareGenerator) encryptShare(shareValue []byte, dek *DataEncryptionKey) (EncryptedBlob, error) {
    // Generate random IV
    var iv [12]byte
    if _, err := rand.Read(iv[:]); err != nil {
        return EncryptedBlob{}, err
    }

    // Create AES-GCM cipher
    block, err := aes.NewCipher(dek.Key)
    if err != nil {
        return EncryptedBlob{}, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return EncryptedBlob{}, err
    }

    // Encrypt with additional authenticated data
    aad := sg.computeAAD(dek.KeyID)
    ciphertext := gcm.Seal(nil, iv[:], shareValue, aad)

    // Extract auth tag (last 16 bytes)
    var authTag [16]byte
    copy(authTag[:], ciphertext[len(ciphertext)-16:])

    return EncryptedBlob{
        Algorithm:  "AES-256-GCM",
        KeyID:      dek.KeyID,
        IV:         iv,
        AuthTag:    authTag,
        Ciphertext: ciphertext[:len(ciphertext)-16],
        KeyVersion: dek.Version,
    }, nil
}
```

### Storage: Accessing Shares for Signing

When a share is needed for FROST signing, it must be securely retrieved:

```go
// ShareAccessor handles secure share retrieval for signing operations
type ShareAccessor struct {
    kms           KMSBackend
    tpm           TPMInterface
    auditLog      AuditLogger
    rateLimiter   RateLimiter
}

// RetrieveShare securely retrieves and decrypts a share for signing
func (sa *ShareAccessor) RetrieveShare(
    ctx context.Context,
    shareID [32]byte,
    signingRequest *FROSTSigningRequest,
) (*DecryptedShare, error) {
    // Step 1: Rate limiting
    if !sa.rateLimiter.Allow(shareID) {
        return nil, ErrShareAccessRateLimited{ShareID: shareID}
    }

    // Step 2: Load share record from KMS
    record, err := sa.kms.GetShareRecord(ctx, shareID)
    if err != nil {
        return nil, ErrShareNotFound{ShareID: shareID, Cause: err}
    }

    // Step 3: Validate share status
    if record.Metadata.Status != ShareStatusActive {
        return nil, ErrShareNotActive{ShareID: shareID, Status: record.Metadata.Status}
    }

    // Step 4: Check expiration
    if time.Now().After(record.Metadata.ExpiresAt) {
        return nil, ErrShareExpired{ShareID: shareID, ExpiredAt: record.Metadata.ExpiresAt}
    }

    // Step 5: Retrieve encrypted DEK from KMS
    encryptedDEK, err := sa.kms.GetEncryptedDEK(ctx, record.KeyReference, record.SecretShare.KeyID)
    if err != nil {
        return nil, ErrDEKRetrievalFailed{Cause: err}
    }

    // Step 6: Decrypt DEK using KEK in KMS
    dekBytes, err := sa.kms.DecryptWithKEK(ctx, record.KeyReference, encryptedDEK)
    if err != nil {
        return nil, ErrDEKDecryptionFailed{Cause: err}
    }

    // Step 7: Decrypt share using DEK
    shareValue, err := sa.decryptShare(record.SecretShare, dekBytes)
    if err != nil {
        // Secure wipe DEK from memory
        secureWipe(dekBytes)
        return nil, ErrShareDecryptionFailed{Cause: err}
    }

    // Step 8: Verify share against public commitment
    if !sa.verifyShareCommitment(shareValue, record.PublicCommitment) {
        secureWipe(dekBytes)
        secureWipe(shareValue)
        return nil, ErrShareCommitmentMismatch{ShareID: shareID}
    }

    // Step 9: Update access metadata
    sa.updateAccessMetadata(ctx, shareID)

    // Step 10: Audit log
    sa.auditLog.LogShareAccess(ctx, shareID, signingRequest.RequestID)

    // Step 11: Secure wipe DEK (share remains for signing)
    secureWipe(dekBytes)

    return &DecryptedShare{
        ShareID:    shareID,
        Index:      record.ShareIndex,
        Value:      shareValue,
        ValidUntil: time.Now().Add(30 * time.Second), // Short-lived
        Cleanup:    func() { secureWipe(shareValue) },
    }, nil
}

// DecryptedShare holds a temporarily decrypted share
type DecryptedShare struct {
    ShareID    [32]byte
    Index      uint16
    Value      []byte
    ValidUntil time.Time
    Cleanup    func() // Must be called after use
}
```

### Rotation: Coordinated Share Refresh

Share rotation is coordinated with DKG refresh to maintain security:

```go
// ShareRotationCoordinator manages share rotation lifecycle
type ShareRotationCoordinator struct {
    kms           KMSBackend
    dkgClient     DKGClient
    auditLog      AuditLogger
    retentionDays int
}

// RotationTrigger defines what initiates rotation
type RotationTrigger uint8

const (
    RotationTriggerScheduled   RotationTrigger = iota // Regular schedule
    RotationTriggerExpiration                         // Share approaching expiration
    RotationTriggerCompromise                         // Suspected compromise
    RotationTriggerCARotation                         // CA epoch rotation
    RotationTriggerMemberChange                       // Pool membership change
)

// ShareRotationRequest initiates a share rotation
type ShareRotationRequest struct {
    GroupID         [32]byte
    Trigger         RotationTrigger
    RequestedBy     [32]byte        // Node ID of requester
    RetainOldShares time.Duration   // How long to keep old shares
}

// RotateShares coordinates share rotation with DKG refresh
func (src *ShareRotationCoordinator) RotateShares(
    ctx context.Context,
    request ShareRotationRequest,
) (*ShareRotationResult, error) {
    // Step 1: Mark existing shares as rotating
    if err := src.markSharesRotating(ctx, request.GroupID); err != nil {
        return nil, ErrRotationMarkFailed{Cause: err}
    }

    // Step 2: Initiate DKG refresh round
    refreshSession, err := src.dkgClient.InitiateRefresh(ctx, request.GroupID)
    if err != nil {
        // Revert rotation status
        src.revertRotationStatus(ctx, request.GroupID)
        return nil, ErrDKGRefreshFailed{Cause: err}
    }

    // Step 3: Wait for DKG refresh completion
    newShares, err := src.dkgClient.WaitForRefreshCompletion(ctx, refreshSession)
    if err != nil {
        src.revertRotationStatus(ctx, request.GroupID)
        return nil, ErrDKGRefreshTimeout{Cause: err}
    }

    // Step 4: Store new shares with incremented version
    newVersion := src.getNextVersion(ctx, request.GroupID)
    for _, share := range newShares {
        if err := src.storeRotatedShare(ctx, share, request.GroupID, newVersion); err != nil {
            return nil, ErrRotatedShareStorageFailed{Cause: err}
        }
    }

    // Step 5: Schedule old share expiration
    retentionPeriod := request.RetainOldShares
    if retentionPeriod == 0 {
        retentionPeriod = time.Duration(src.retentionDays) * 24 * time.Hour
    }
    src.scheduleOldShareExpiration(ctx, request.GroupID, newVersion-1, retentionPeriod)

    // Step 6: Audit log
    src.auditLog.LogShareRotation(ctx, request.GroupID, newVersion, request.Trigger)

    return &ShareRotationResult{
        GroupID:        request.GroupID,
        OldVersion:     newVersion - 1,
        NewVersion:     newVersion,
        SharesRotated:  len(newShares),
        OldShareExpiry: time.Now().Add(retentionPeriod),
    }, nil
}

// ShareRotationResult contains the outcome of rotation
type ShareRotationResult struct {
    GroupID        [32]byte
    OldVersion     uint32
    NewVersion     uint32
    SharesRotated  int
    OldShareExpiry time.Time
}
```

### Backup: Encrypted Secure Storage

Shares are backed up using a 3-tier strategy:

```go
// ShareBackupManager handles share backup operations
type ShareBackupManager struct {
    primaryKMS    KMSBackend      // TPM
    secondaryKMS  KMSBackend      // HSM
    coldStorage   ColdStorageBackend
    auditLog      AuditLogger
}

// BackupTier defines backup storage levels
type BackupTier uint8

const (
    BackupTierPrimary   BackupTier = iota // TPM-sealed on local node
    BackupTierSecondary                   // HSM in same region
    BackupTierTertiary                    // Cold storage (geographically distributed)
)

// ShareBackupConfig defines backup policy
type ShareBackupConfig struct {
    // Primary: TPM-sealed local storage
    PrimaryEnabled     bool
    PrimaryRetention   time.Duration // 90 days default

    // Secondary: HSM backup
    SecondaryEnabled   bool
    SecondaryEndpoint  string
    SecondaryRetention time.Duration // 180 days default

    // Tertiary: Cold storage (geographically distributed)
    TertiaryEnabled    bool
    TertiaryLocations  []string      // ["us-east-1", "eu-west-1", "ap-northeast-1"]
    TertiaryRetention  time.Duration // 365 days default

    // Shamir splitting for tertiary (3-of-5 recommended)
    TertiaryShamirN    int           // Total shares
    TertiaryShamirK    int           // Threshold
}

// BackupShare creates encrypted backups across all tiers
func (sbm *ShareBackupManager) BackupShare(
    ctx context.Context,
    shareID [32]byte,
    config ShareBackupConfig,
) (*ShareBackupResult, error) {
    result := &ShareBackupResult{
        ShareID:   shareID,
        BackupID:  generateBackupID(),
        Timestamp: time.Now(),
        Tiers:     make(map[BackupTier]TierBackupStatus),
    }

    // Retrieve share from primary storage
    record, err := sbm.primaryKMS.GetShareRecord(ctx, shareID)
    if err != nil {
        return nil, ErrShareRetrievalFailed{Cause: err}
    }

    // Tier 1: TPM-sealed local backup (already exists as primary)
    if config.PrimaryEnabled {
        result.Tiers[BackupTierPrimary] = TierBackupStatus{
            Success:   true,
            Location:  "tpm://local",
            ExpiresAt: time.Now().Add(config.PrimaryRetention),
        }
    }

    // Tier 2: HSM backup
    if config.SecondaryEnabled {
        hsmStatus, err := sbm.backupToHSM(ctx, record, config)
        if err != nil {
            result.Tiers[BackupTierSecondary] = TierBackupStatus{
                Success: false,
                Error:   err.Error(),
            }
        } else {
            result.Tiers[BackupTierSecondary] = hsmStatus
        }
    }

    // Tier 3: Cold storage with Shamir splitting
    if config.TertiaryEnabled {
        coldStatus, err := sbm.backupToColdStorage(ctx, record, config)
        if err != nil {
            result.Tiers[BackupTierTertiary] = TierBackupStatus{
                Success: false,
                Error:   err.Error(),
            }
        } else {
            result.Tiers[BackupTierTertiary] = coldStatus
        }
    }

    // Audit log
    sbm.auditLog.LogShareBackup(ctx, shareID, result.BackupID, result.Tiers)

    return result, nil
}

// backupToColdStorage creates Shamir-split cold storage backup
func (sbm *ShareBackupManager) backupToColdStorage(
    ctx context.Context,
    record *FROSTShareRecord,
    config ShareBackupConfig,
) (TierBackupStatus, error) {
    // Generate backup encryption key
    backupKey, err := generateBackupKey()
    if err != nil {
        return TierBackupStatus{}, err
    }

    // Encrypt share with backup key
    encryptedShare, err := encryptForColdStorage(record, backupKey)
    if err != nil {
        return TierBackupStatus{}, err
    }

    // Shamir split the backup key
    keyShares, err := shamirSplit(backupKey, config.TertiaryShamirN, config.TertiaryShamirK)
    if err != nil {
        return TierBackupStatus{}, err
    }

    // Distribute key shares across geographic locations
    locations := make([]string, len(config.TertiaryLocations))
    for i, location := range config.TertiaryLocations {
        if i < len(keyShares) {
            if err := sbm.coldStorage.Store(ctx, location, keyShares[i], encryptedShare); err != nil {
                return TierBackupStatus{}, err
            }
            locations[i] = location
        }
    }

    // Secure wipe backup key
    secureWipe(backupKey)

    return TierBackupStatus{
        Success:       true,
        Location:      fmt.Sprintf("cold://%d-of-%d", config.TertiaryShamirK, config.TertiaryShamirN),
        ExpiresAt:     time.Now().Add(config.TertiaryRetention),
        ShamirShares:  config.TertiaryShamirN,
        ShamirK:       config.TertiaryShamirK,
        GeoLocations:  locations,
    }, nil
}

// ShareBackupResult contains backup operation results
type ShareBackupResult struct {
    ShareID   [32]byte
    BackupID  [32]byte
    Timestamp time.Time
    Tiers     map[BackupTier]TierBackupStatus
}

// TierBackupStatus contains per-tier backup status
type TierBackupStatus struct {
    Success      bool
    Location     string
    ExpiresAt    time.Time
    Error        string
    ShamirShares int
    ShamirK      int
    GeoLocations []string
}
```

### Recovery: Share Re-derivation

When shares are lost, they can be recovered from backups or through DKG re-enrollment:

```go
// ShareRecoveryManager handles share recovery operations
type ShareRecoveryManager struct {
    kms           KMSBackend
    dkgClient     DKGClient
    backupManager *ShareBackupManager
    auditLog      AuditLogger
}

// RecoverySource defines where recovery data comes from
type RecoverySource uint8

const (
    RecoverySourcePrimaryBackup   RecoverySource = iota // TPM backup on node
    RecoverySourceSecondaryBackup                       // HSM backup
    RecoverySourceTertiaryBackup                        // Cold storage
    RecoverySourceDKGReEnroll                           // Fresh DKG enrollment
)

// ShareRecoveryRequest initiates share recovery
type ShareRecoveryRequest struct {
    NodeID       [32]byte
    GroupID      [32]byte
    Source       RecoverySource
    Reason       string
    ApprovedBy   []string          // Required approvers for cold storage
    TPMQuote     []byte            // Fresh TPM attestation
}

// RecoverShare attempts to recover a share from the specified source
func (srm *ShareRecoveryManager) RecoverShare(
    ctx context.Context,
    request ShareRecoveryRequest,
) (*ShareRecoveryResult, error) {
    // Step 1: Verify TPM attestation
    if err := srm.verifyTPMAttestation(request.TPMQuote, request.NodeID); err != nil {
        return nil, ErrTPMAttestationFailed{Cause: err}
    }

    var result *ShareRecoveryResult
    var err error

    switch request.Source {
    case RecoverySourcePrimaryBackup:
        result, err = srm.recoverFromTPM(ctx, request)

    case RecoverySourceSecondaryBackup:
        result, err = srm.recoverFromHSM(ctx, request)

    case RecoverySourceTertiaryBackup:
        // Requires multi-party approval
        if err := srm.verifyApprovals(ctx, request.ApprovedBy); err != nil {
            return nil, ErrRecoveryApprovalRequired{Cause: err}
        }
        result, err = srm.recoverFromColdStorage(ctx, request)

    case RecoverySourceDKGReEnroll:
        result, err = srm.initiateReEnrollment(ctx, request)
    }

    if err != nil {
        return nil, err
    }

    // Audit log
    srm.auditLog.LogShareRecovery(ctx, request.NodeID, request.GroupID, request.Source, result.Success)

    return result, nil
}

// initiateReEnrollment performs DKG re-enrollment for complete share loss
func (srm *ShareRecoveryManager) initiateReEnrollment(
    ctx context.Context,
    request ShareRecoveryRequest,
) (*ShareRecoveryResult, error) {
    // Step 1: Request re-enrollment from pool coordinator
    reEnrollReq := &DKGReEnrollmentRequest{
        NodeID:         request.NodeID,
        GroupID:        request.GroupID,
        Reason:         request.Reason,
        TPMAttestation: request.TPMQuote,
        Timestamp:      time.Now(),
    }

    // Step 2: Pool must verify node identity and approve
    approval, err := srm.dkgClient.RequestReEnrollment(ctx, reEnrollReq)
    if err != nil {
        return nil, ErrReEnrollmentRejected{Cause: err}
    }

    // Step 3: Participate in DKG refresh round (node gets new share)
    session, err := srm.dkgClient.ParticipateInRefresh(ctx, approval.SessionID)
    if err != nil {
        return nil, ErrReEnrollmentDKGFailed{Cause: err}
    }

    // Step 4: Store new share
    newShareID, err := srm.kms.StoreNewShare(ctx, session.NewShare, request.GroupID)
    if err != nil {
        return nil, ErrShareStorageFailed{Cause: err}
    }

    return &ShareRecoveryResult{
        Success:     true,
        Source:      RecoverySourceDKGReEnroll,
        ShareID:     newShareID,
        NewVersion:  session.Version,
        RecoveredAt: time.Now(),
    }, nil
}

// ShareRecoveryResult contains recovery operation results
type ShareRecoveryResult struct {
    Success     bool
    Source      RecoverySource
    ShareID     [32]byte
    NewVersion  uint32
    RecoveredAt time.Time
    Error       string
}
```

---

## TPM-KMS Integration

### Key Hierarchy

The TPM-KMS integration uses a hierarchical key structure:

```
+------------------------------------------------------------------+
|                        Key Hierarchy                              |
+------------------------------------------------------------------+
|                                                                    |
|  TPM Endorsement Key (EK)                                         |
|  └── Immutable, manufacturer-provisioned                          |
|      │                                                            |
|      v                                                            |
|  TPM Storage Root Key (SRK)                                       |
|  └── Platform master key, never leaves TPM                        |
|      │                                                            |
|      +──> TPM Attestation Identity Key (AIK)                      |
|      │    └── Signs TPM quotes                                    |
|      │                                                            |
|      +──> Share Sealing Key (SSK)                                 |
|      │    └── Encrypts FROST shares at rest                       |
|      │                                                            |
|      +──> Identity Share Key (ISK)                                |
|           └── PCR-bound key for identity-critical shares          |
|                                                                    |
+------------------------------------------------------------------+
```

### Key Distribution by Backend

```go
// KeyLocationPolicy defines where each key type is stored
type KeyLocationPolicy struct {
    // Keys stored exclusively in TPM
    TPMOnlyKeys []KeyType

    // Keys stored in external KMS (HSM, Cloud)
    ExternalKMSKeys []KeyType

    // Keys replicated across TPM and external KMS
    ReplicatedKeys []KeyType
}

// DefaultKeyLocationPolicy returns the recommended key distribution
func DefaultKeyLocationPolicy() KeyLocationPolicy {
    return KeyLocationPolicy{
        // TPM-only: Identity-critical keys that must not leave hardware
        TPMOnlyKeys: []KeyType{
            KeyTypeEK,              // Endorsement Key
            KeyTypeSRK,             // Storage Root Key
            KeyTypeAIK,             // Attestation Identity Key
            KeyTypeISK,             // Identity Share Key (PCR-bound)
            KeyTypeNonceSealing,    // FROST nonce sealing key
        },

        // External KMS: Keys that benefit from HSM/Cloud KMS features
        ExternalKMSKeys: []KeyType{
            KeyTypeKEK,             // Key Encryption Key (for share envelope)
            KeyTypeBackupKey,       // Backup encryption key
            KeyTypeTransportKey,    // Key for encrypted P2P transfer
        },

        // Replicated: Keys stored in both for redundancy
        ReplicatedKeys: []KeyType{
            KeyTypeDEK,             // Data Encryption Key (share encryption)
        },
    }
}

// KeyType identifies different key purposes
type KeyType string

const (
    KeyTypeEK            KeyType = "endorsement_key"
    KeyTypeSRK           KeyType = "storage_root_key"
    KeyTypeAIK           KeyType = "attestation_identity_key"
    KeyTypeISK           KeyType = "identity_share_key"
    KeyTypeNonceSealing  KeyType = "nonce_sealing_key"
    KeyTypeKEK           KeyType = "key_encryption_key"
    KeyTypeDEK           KeyType = "data_encryption_key"
    KeyTypeBackupKey     KeyType = "backup_key"
    KeyTypeTransportKey  KeyType = "transport_key"
)
```

### TPM-Sealed Share Encryption

```go
// TPMShareSealer handles TPM-based share protection
type TPMShareSealer struct {
    tpm         TPMInterface
    pcrPolicy   PCRSelection
    auditLog    AuditLogger
}

// SealShareToTPM seals a FROST share with PCR policy
func (tss *TPMShareSealer) SealShareToTPM(
    ctx context.Context,
    shareValue []byte,
    metadata ShareMetadata,
) (*TPMSealedShare, error) {
    // Step 1: Read current PCR values
    currentPCRs, err := tss.tpm.ReadPCRs(ctx, tss.pcrPolicy.PCRIndices)
    if err != nil {
        return nil, ErrPCRReadFailed{Cause: err}
    }

    // Step 2: Create policy session with PCR binding
    policySession, err := tss.tpm.StartPolicySession(ctx)
    if err != nil {
        return nil, ErrPolicySessionFailed{Cause: err}
    }
    defer tss.tpm.FlushContext(ctx, policySession)

    // Step 3: Add PCR policy to session
    if err := tss.tpm.PolicyPCR(ctx, policySession, tss.pcrPolicy.PCRIndices); err != nil {
        return nil, ErrPolicyPCRFailed{Cause: err}
    }

    // Step 4: Get policy digest
    policyDigest, err := tss.tpm.PolicyGetDigest(ctx, policySession)
    if err != nil {
        return nil, ErrPolicyDigestFailed{Cause: err}
    }

    // Step 5: Create sealing key with policy
    sealingKeyHandle, err := tss.tpm.CreateSealingKey(ctx, policyDigest)
    if err != nil {
        return nil, ErrSealingKeyCreationFailed{Cause: err}
    }

    // Step 6: Seal the share data
    sealedBlob, err := tss.tpm.Seal(ctx, sealingKeyHandle, shareValue)
    if err != nil {
        return nil, ErrSealingFailed{Cause: err}
    }

    // Step 7: Store PCR values at seal time (for audit)
    expectedValues := make(map[int][32]byte)
    for i, pcr := range currentPCRs {
        var pcrValue [32]byte
        copy(pcrValue[:], pcr)
        expectedValues[tss.pcrPolicy.PCRIndices[i]] = pcrValue
    }

    return &TPMSealedShare{
        SealedBlob:     sealedBlob,
        ParentHandle:   TPMSRKHandle,
        PCRSelection: PCRSelection{
            HashAlgorithm:  tss.pcrPolicy.HashAlgorithm,
            PCRIndices:     tss.pcrPolicy.PCRIndices,
            ExpectedValues: expectedValues,
        },
        PolicyDigest:  policyDigest,
        SealedAt:      time.Now(),
        TPMVendor:     tss.tpm.Vendor(),
        TPMFirmware:   tss.tpm.FirmwareVersion(),
    }, nil
}

// UnsealShareFromTPM unseals a share if PCR values match
func (tss *TPMShareSealer) UnsealShareFromTPM(
    ctx context.Context,
    sealed *TPMSealedShare,
) ([]byte, error) {
    // Step 1: Verify current PCRs against sealed policy
    currentPCRs, err := tss.tpm.ReadPCRs(ctx, sealed.PCRSelection.PCRIndices)
    if err != nil {
        return nil, ErrPCRReadFailed{Cause: err}
    }

    // Step 2: Check PCR values match
    for i, idx := range sealed.PCRSelection.PCRIndices {
        expected := sealed.PCRSelection.ExpectedValues[idx]
        if !bytes.Equal(currentPCRs[i], expected[:]) {
            return nil, ErrPCRPolicyViolation{
                PCRIndex:  idx,
                Expected:  expected[:],
                Actual:    currentPCRs[i],
            }
        }
    }

    // Step 3: Create policy session
    policySession, err := tss.tpm.StartPolicySession(ctx)
    if err != nil {
        return nil, ErrPolicySessionFailed{Cause: err}
    }
    defer tss.tpm.FlushContext(ctx, policySession)

    // Step 4: Satisfy PCR policy
    if err := tss.tpm.PolicyPCR(ctx, policySession, sealed.PCRSelection.PCRIndices); err != nil {
        return nil, ErrPolicyPCRFailed{Cause: err}
    }

    // Step 5: Unseal with policy session
    shareValue, err := tss.tpm.Unseal(ctx, policySession, sealed.SealedBlob)
    if err != nil {
        return nil, ErrUnsealingFailed{Cause: err}
    }

    // Audit log
    tss.auditLog.LogShareUnseal(ctx, sealed.PolicyDigest)

    return shareValue, nil
}
```

### TPM NVRAM for Persistent Shares

Critical identity shares can be stored in TPM NVRAM for persistence:

```go
// NVRAMShareStorage handles persistent share storage in TPM NVRAM
type NVRAMShareStorage struct {
    tpm       TPMInterface
    auditLog  AuditLogger
}

// NVRAMShareConfig configures NVRAM storage
type NVRAMShareConfig struct {
    // NVRAM index allocation
    BaseIndex     uint32  // Starting NVRAM index (0x01500000 recommended)
    MaxShares     int     // Maximum shares to store in NVRAM

    // Access control
    OwnerAuth     []byte  // Owner authorization
    PolicyDigest  []byte  // Policy for read/write access

    // Storage options
    WriteOnce     bool    // NVRAM write-once mode (for root of trust)
    Persistent    bool    // Survive TPM2_Clear
}

// StoreShareInNVRAM persists a share to TPM NVRAM
func (nss *NVRAMShareStorage) StoreShareInNVRAM(
    ctx context.Context,
    shareID [32]byte,
    encryptedShare []byte,
    config NVRAMShareConfig,
) (uint32, error) {
    // Step 1: Find available NVRAM index
    nvIndex := nss.allocateNVIndex(config.BaseIndex, config.MaxShares)
    if nvIndex == 0 {
        return 0, ErrNVRAMFull{}
    }

    // Step 2: Define NVRAM space
    nvAttrs := tpm2.NVTypeOrdinary
    if config.WriteOnce {
        nvAttrs |= tpm2.NVWriteDefine
    }

    nvPublic := tpm2.NVPublic{
        NVIndex:    tpm2.TPMHandle(nvIndex),
        NameAlg:    tpm2.TPMAlgSHA256,
        Attributes: nvAttrs | tpm2.NVOwnerWrite | tpm2.NVOwnerRead,
        DataSize:   uint16(len(encryptedShare)),
    }

    if err := nss.tpm.NVDefineSpace(ctx, config.OwnerAuth, nvPublic); err != nil {
        return 0, ErrNVDefineSpaceFailed{Cause: err}
    }

    // Step 3: Write share to NVRAM
    if err := nss.tpm.NVWrite(ctx, nvIndex, encryptedShare, config.OwnerAuth); err != nil {
        // Clean up on failure
        nss.tpm.NVUndefineSpace(ctx, nvIndex, config.OwnerAuth)
        return 0, ErrNVWriteFailed{Cause: err}
    }

    // Step 4: Register in index map
    nss.registerNVIndex(shareID, nvIndex)

    // Audit log
    nss.auditLog.LogNVRAMStore(ctx, shareID, nvIndex)

    return nvIndex, nil
}

// ReadShareFromNVRAM reads a share from TPM NVRAM
func (nss *NVRAMShareStorage) ReadShareFromNVRAM(
    ctx context.Context,
    nvIndex uint32,
    ownerAuth []byte,
) ([]byte, error) {
    // Step 1: Read NVRAM public to get size
    nvPublic, err := nss.tpm.NVReadPublic(ctx, nvIndex)
    if err != nil {
        return nil, ErrNVReadPublicFailed{Cause: err}
    }

    // Step 2: Read NVRAM data
    data, err := nss.tpm.NVRead(ctx, nvIndex, nvPublic.DataSize, 0, ownerAuth)
    if err != nil {
        return nil, ErrNVReadFailed{Cause: err}
    }

    // Audit log
    nss.auditLog.LogNVRAMRead(ctx, nvIndex)

    return data, nil
}
```

---

## FROST Share Refresh Protocol

### Proactive Share Renewal

Share refresh renews shares without changing the group public key:

```go
// ShareRefreshProtocol implements proactive secret sharing
type ShareRefreshProtocol struct {
    dkgClient     DKGClient
    kms           KMSBackend
    auditLog      AuditLogger
}

// RefreshSchedule defines when refresh occurs
type RefreshSchedule struct {
    // Regular refresh interval
    Interval       time.Duration  // 30 days default

    // CA-synchronized refresh (hourly CA rotation)
    CAEpochAligned bool           // Refresh on CA epoch boundaries

    // Share expiration buffer
    ExpirationBuffer time.Duration // Refresh 7 days before expiration
}

// DefaultRefreshSchedule returns recommended refresh settings
func DefaultRefreshSchedule() RefreshSchedule {
    return RefreshSchedule{
        Interval:         30 * 24 * time.Hour,
        CAEpochAligned:   true,
        ExpirationBuffer: 7 * 24 * time.Hour,
    }
}

// RefreshState tracks refresh progress across participants
type RefreshState struct {
    GroupID          [32]byte
    RefreshID        [32]byte
    InitiatedAt      time.Time
    CurrentPhase     RefreshPhase
    Participants     map[[32]byte]ParticipantRefreshStatus
    OldVersion       uint32
    NewVersion       uint32
    CompletedAt      time.Time
}

// RefreshPhase indicates current refresh protocol phase
type RefreshPhase uint8

const (
    RefreshPhaseInitiated    RefreshPhase = iota // Refresh announced
    RefreshPhaseCommitments                      // Collecting refresh commitments
    RefreshPhaseShares                           // Distributing refresh shares
    RefreshPhaseVerification                     // Verifying new shares
    RefreshPhaseActivation                       // Activating new shares
    RefreshPhaseCleanup                          // Cleaning old shares
    RefreshPhaseComplete                         // Refresh finished
)

// ParticipantRefreshStatus tracks individual participant progress
type ParticipantRefreshStatus struct {
    NodeID           [32]byte
    CommitmentSent   bool
    SharesReceived   bool
    VerificationDone bool
    NewShareStored   bool
    OldShareDeleted  bool
}

// InitiateRefresh starts the share refresh protocol
func (srp *ShareRefreshProtocol) InitiateRefresh(
    ctx context.Context,
    groupID [32]byte,
    reason string,
) (*RefreshState, error) {
    // Step 1: Create refresh session
    refreshID := generateRefreshID()
    currentVersion := srp.getCurrentShareVersion(ctx, groupID)

    state := &RefreshState{
        GroupID:      groupID,
        RefreshID:    refreshID,
        InitiatedAt:  time.Now(),
        CurrentPhase: RefreshPhaseInitiated,
        OldVersion:   currentVersion,
        NewVersion:   currentVersion + 1,
        Participants: make(map[[32]byte]ParticipantRefreshStatus),
    }

    // Step 2: Announce refresh to all pool members
    announcement := &RefreshAnnouncement{
        GroupID:    groupID,
        RefreshID:  refreshID,
        OldVersion: currentVersion,
        NewVersion: currentVersion + 1,
        Reason:     reason,
        Deadline:   time.Now().Add(5 * time.Minute),
    }

    if err := srp.dkgClient.BroadcastRefreshAnnouncement(ctx, announcement); err != nil {
        return nil, ErrRefreshAnnouncementFailed{Cause: err}
    }

    // Step 3: Collect acknowledgments
    if err := srp.waitForAcknowledgments(ctx, state); err != nil {
        return nil, ErrRefreshAcknowledgmentTimeout{Cause: err}
    }

    // Step 4: Execute refresh DKG
    if err := srp.executeRefreshDKG(ctx, state); err != nil {
        return nil, ErrRefreshDKGFailed{Cause: err}
    }

    // Step 5: Verify all participants have new shares
    if err := srp.verifyRefreshCompletion(ctx, state); err != nil {
        return nil, ErrRefreshVerificationFailed{Cause: err}
    }

    // Step 6: Activate new shares
    state.CurrentPhase = RefreshPhaseActivation
    if err := srp.activateNewShares(ctx, state); err != nil {
        return nil, ErrShareActivationFailed{Cause: err}
    }

    // Step 7: Schedule old share cleanup
    state.CurrentPhase = RefreshPhaseCleanup
    srp.scheduleOldShareCleanup(ctx, groupID, currentVersion)

    state.CurrentPhase = RefreshPhaseComplete
    state.CompletedAt = time.Now()

    // Audit log
    srp.auditLog.LogRefreshComplete(ctx, state)

    return state, nil
}

// executeRefreshDKG runs the refresh-specific DKG round
func (srp *ShareRefreshProtocol) executeRefreshDKG(
    ctx context.Context,
    state *RefreshState,
) error {
    // Refresh DKG generates additive shares that sum to zero
    // Adding these to existing shares creates new shares
    // but the group public key remains unchanged

    state.CurrentPhase = RefreshPhaseCommitments

    // Phase 1: Generate and broadcast refresh commitments
    refreshSession, err := srp.dkgClient.StartRefreshSession(ctx, state.GroupID, state.RefreshID)
    if err != nil {
        return err
    }

    // Phase 2: Distribute refresh shares
    state.CurrentPhase = RefreshPhaseShares
    if err := srp.dkgClient.DistributeRefreshShares(ctx, refreshSession); err != nil {
        return err
    }

    // Phase 3: Verify and combine
    state.CurrentPhase = RefreshPhaseVerification
    newShares, err := srp.dkgClient.CombineRefreshShares(ctx, refreshSession)
    if err != nil {
        return err
    }

    // Store new shares
    for nodeID, share := range newShares {
        if err := srp.storeRefreshedShare(ctx, nodeID, share, state); err != nil {
            return err
        }
        state.Participants[nodeID] = ParticipantRefreshStatus{
            NodeID:           nodeID,
            CommitmentSent:   true,
            SharesReceived:   true,
            VerificationDone: true,
            NewShareStored:   true,
        }
    }

    return nil
}
```

### Coordination with CA Rotation

Share refresh is synchronized with hourly CA epoch rotation:

```go
// CAEpochCoordinator synchronizes share refresh with CA rotation
type CAEpochCoordinator struct {
    refreshProtocol *ShareRefreshProtocol
    caClient        CAClient
    schedule        RefreshSchedule
}

// EpochRefreshPolicy defines how refresh aligns with CA epochs
type EpochRefreshPolicy struct {
    // Refresh during CA epoch transition window
    TransitionWindow time.Duration  // 10 minutes before/after epoch

    // Maximum epoch skew before forced refresh
    MaxEpochSkew     uint64         // 24 epochs (24 hours)

    // Backup share retention across epochs
    CrossEpochRetention time.Duration // 2 epochs (2 hours)
}

// CoordinateWithCARotation aligns share refresh with CA epochs
func (cec *CAEpochCoordinator) CoordinateWithCARotation(
    ctx context.Context,
    groupID [32]byte,
) error {
    // Get current CA epoch
    currentEpoch, err := cec.caClient.GetCurrentEpoch(ctx)
    if err != nil {
        return ErrCAEpochQueryFailed{Cause: err}
    }

    // Get share version and epoch alignment
    shareVersion, shareEpoch := cec.getShareVersionAndEpoch(ctx, groupID)

    // Check if refresh needed based on epoch drift
    epochDrift := currentEpoch - shareEpoch
    if epochDrift < cec.schedule.MaxEpochSkew {
        return nil // No refresh needed
    }

    // Wait for optimal refresh window (near epoch boundary)
    if err := cec.waitForRefreshWindow(ctx, currentEpoch); err != nil {
        return err
    }

    // Initiate refresh
    reason := fmt.Sprintf("ca_epoch_alignment: epoch %d -> %d", shareEpoch, currentEpoch)
    _, err = cec.refreshProtocol.InitiateRefresh(ctx, groupID, reason)
    return err
}

// waitForRefreshWindow waits until we're in the CA epoch transition window
func (cec *CAEpochCoordinator) waitForRefreshWindow(
    ctx context.Context,
    currentEpoch uint64,
) error {
    nextEpochStart := cec.caClient.GetEpochStartTime(currentEpoch + 1)
    windowStart := nextEpochStart.Add(-10 * time.Minute)

    select {
    case <-ctx.Done():
        return ctx.Err()
    case <-time.After(time.Until(windowStart)):
        return nil
    }
}
```

### Share Versioning

```go
// ShareVersionManager tracks share versions across the pool
type ShareVersionManager struct {
    kms       KMSBackend
    auditLog  AuditLogger
}

// ShareVersionRecord tracks a specific version
type ShareVersionRecord struct {
    Version       uint32
    CreatedAt     time.Time
    ExpiresAt     time.Time
    Status        ShareVersionStatus
    DKGSessionID  [32]byte
    ParticipantCount uint16
}

// ShareVersionStatus indicates version state
type ShareVersionStatus uint8

const (
    ShareVersionActive   ShareVersionStatus = iota // Currently in use
    ShareVersionPending                            // Being activated
    ShareVersionExpiring                           // Being phased out
    ShareVersionExpired                            // No longer valid
    ShareVersionRevoked                            // Explicitly revoked
)

// GetActiveVersion returns the current active share version
func (svm *ShareVersionManager) GetActiveVersion(
    ctx context.Context,
    groupID [32]byte,
) (*ShareVersionRecord, error) {
    versions, err := svm.kms.ListShareVersions(ctx, groupID)
    if err != nil {
        return nil, err
    }

    for _, v := range versions {
        if v.Status == ShareVersionActive {
            return v, nil
        }
    }

    return nil, ErrNoActiveShareVersion{GroupID: groupID}
}

// TransitionVersion handles version activation and expiration
func (svm *ShareVersionManager) TransitionVersion(
    ctx context.Context,
    groupID [32]byte,
    newVersion uint32,
) error {
    // Mark current active version as expiring
    current, err := svm.GetActiveVersion(ctx, groupID)
    if err != nil {
        return err
    }

    current.Status = ShareVersionExpiring
    current.ExpiresAt = time.Now().Add(2 * time.Hour) // 2 epoch retention

    if err := svm.kms.UpdateShareVersion(ctx, groupID, current); err != nil {
        return err
    }

    // Activate new version
    newRecord := &ShareVersionRecord{
        Version:   newVersion,
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
        Status:    ShareVersionActive,
    }

    if err := svm.kms.UpdateShareVersion(ctx, groupID, newRecord); err != nil {
        return err
    }

    // Audit log
    svm.auditLog.LogVersionTransition(ctx, groupID, current.Version, newVersion)

    return nil
}
```

### Old Share Expiration

```go
// ShareExpirationManager handles secure deletion of expired shares
type ShareExpirationManager struct {
    kms           KMSBackend
    tpm           TPMInterface
    auditLog      AuditLogger
}

// ExpireOldShares securely deletes shares past their retention period
func (sem *ShareExpirationManager) ExpireOldShares(
    ctx context.Context,
    groupID [32]byte,
) (*ExpirationResult, error) {
    result := &ExpirationResult{
        GroupID:    groupID,
        ProcessedAt: time.Now(),
    }

    // Get all share versions
    versions, err := sem.kms.ListShareVersions(ctx, groupID)
    if err != nil {
        return nil, err
    }

    for _, v := range versions {
        if v.Status == ShareVersionExpiring && time.Now().After(v.ExpiresAt) {
            // Secure delete expired version
            if err := sem.secureDeleteVersion(ctx, groupID, v.Version); err != nil {
                result.Failures = append(result.Failures, ExpirationFailure{
                    Version: v.Version,
                    Error:   err.Error(),
                })
                continue
            }

            result.ExpiredVersions = append(result.ExpiredVersions, v.Version)
        }
    }

    // Audit log
    sem.auditLog.LogShareExpiration(ctx, groupID, result)

    return result, nil
}

// secureDeleteVersion performs cryptographic erasure of a share version
func (sem *ShareExpirationManager) secureDeleteVersion(
    ctx context.Context,
    groupID [32]byte,
    version uint32,
) error {
    // Step 1: Delete DEK from KMS (makes share unrecoverable)
    dekID := fmt.Sprintf("%x-v%d-dek", groupID[:8], version)
    if err := sem.kms.DeleteKey(ctx, dekID); err != nil {
        return err
    }

    // Step 2: If TPM-sealed, undefine NVRAM space
    nvIndex, err := sem.kms.GetNVIndexForShare(ctx, groupID, version)
    if err == nil && nvIndex != 0 {
        if err := sem.tpm.NVUndefineSpace(ctx, nvIndex, nil); err != nil {
            return err
        }
    }

    // Step 3: Delete encrypted share blob
    shareID := computeShareID(groupID, version)
    if err := sem.kms.DeleteShareRecord(ctx, shareID); err != nil {
        return err
    }

    // Step 4: Update version status
    return sem.kms.MarkVersionExpired(ctx, groupID, version)
}

// ExpirationResult contains the outcome of expiration processing
type ExpirationResult struct {
    GroupID          [32]byte
    ProcessedAt      time.Time
    ExpiredVersions  []uint32
    Failures         []ExpirationFailure
}

// ExpirationFailure records a failed expiration attempt
type ExpirationFailure struct {
    Version uint32
    Error   string
}
```

---

## Backup and Recovery

### 3-Tier Backup Strategy

```
+------------------------------------------------------------------+
|                   FROST Share Backup Architecture                 |
+------------------------------------------------------------------+
|                                                                    |
|  Tier 1: TPM-Sealed Local Storage                                 |
|  ├── Location: Local TPM NVRAM                                    |
|  ├── Protection: PCR-bound sealing policy                         |
|  ├── Retention: 90 days                                           |
|  ├── Recovery: Automatic on node restart (if PCRs match)          |
|  └── Use case: Primary storage, fastest access                    |
|                                                                    |
|  Tier 2: HSM Backup (Regional)                                    |
|  ├── Location: Cloud HSM (same region)                            |
|  ├── Protection: HSM-managed keys, RBAC                           |
|  ├── Retention: 180 days                                          |
|  ├── Recovery: API call with authentication                       |
|  └── Use case: Node failure, TPM replacement                      |
|                                                                    |
|  Tier 3: Cold Storage (Geographic)                                |
|  ├── Location: Secure vaults (3 regions minimum)                  |
|  ├── Protection: Shamir split (3-of-5), air-gapped                |
|  ├── Retention: 365 days                                          |
|  ├── Recovery: Multi-party authorization required                 |
|  └── Use case: Regional disaster, complete loss                   |
|                                                                    |
+------------------------------------------------------------------+
```

### Recovery Procedures

#### Lost Share Recovery (Single Node)

```go
// SingleNodeRecovery handles recovery when one node loses its share
type SingleNodeRecovery struct {
    backupManager *ShareBackupManager
    dkgClient     DKGClient
    auditLog      AuditLogger
}

// RecoverSingleNodeShare attempts recovery from available backups
func (snr *SingleNodeRecovery) RecoverSingleNodeShare(
    ctx context.Context,
    nodeID [32]byte,
    groupID [32]byte,
) (*ShareRecoveryResult, error) {
    // Try Tier 1: Local TPM
    result, err := snr.tryTPMRecovery(ctx, nodeID, groupID)
    if err == nil {
        return result, nil
    }

    // Try Tier 2: HSM backup
    result, err = snr.tryHSMRecovery(ctx, nodeID, groupID)
    if err == nil {
        return result, nil
    }

    // Try Tier 3: Cold storage (requires approval workflow)
    result, err = snr.initiateColdStorageRecovery(ctx, nodeID, groupID)
    if err == nil {
        return result, nil
    }

    // Last resort: DKG re-enrollment
    return snr.initiateReEnrollment(ctx, nodeID, groupID)
}

// tryHSMRecovery attempts share recovery from HSM backup
func (snr *SingleNodeRecovery) tryHSMRecovery(
    ctx context.Context,
    nodeID [32]byte,
    groupID [32]byte,
) (*ShareRecoveryResult, error) {
    // Step 1: Authenticate to HSM
    hsmSession, err := snr.backupManager.secondaryKMS.Authenticate(ctx, nodeID)
    if err != nil {
        return nil, ErrHSMAuthenticationFailed{Cause: err}
    }
    defer hsmSession.Close()

    // Step 2: Retrieve encrypted backup
    backupID := snr.findLatestBackup(ctx, nodeID, groupID, BackupTierSecondary)
    if backupID == nil {
        return nil, ErrNoBackupFound{Tier: BackupTierSecondary}
    }

    encryptedBackup, err := snr.backupManager.secondaryKMS.RetrieveBackup(ctx, *backupID)
    if err != nil {
        return nil, ErrBackupRetrievalFailed{Cause: err}
    }

    // Step 3: Decrypt backup using HSM
    shareData, err := snr.backupManager.secondaryKMS.DecryptBackup(ctx, encryptedBackup)
    if err != nil {
        return nil, ErrBackupDecryptionFailed{Cause: err}
    }

    // Step 4: Store recovered share in primary storage
    if err := snr.backupManager.primaryKMS.RestoreShare(ctx, nodeID, groupID, shareData); err != nil {
        secureWipe(shareData)
        return nil, ErrShareRestorationFailed{Cause: err}
    }

    // Step 5: Verify recovered share
    if err := snr.verifyRecoveredShare(ctx, nodeID, groupID); err != nil {
        return nil, ErrShareVerificationFailed{Cause: err}
    }

    // Audit log
    snr.auditLog.LogShareRecovery(ctx, nodeID, groupID, RecoverySourceSecondaryBackup, true)

    return &ShareRecoveryResult{
        Success:     true,
        Source:      RecoverySourceSecondaryBackup,
        RecoveredAt: time.Now(),
    }, nil
}
```

#### DKG Re-enrollment (Complete Share Loss)

```go
// CompleteShareLossRecovery handles recovery when all backups are unavailable
type CompleteShareLossRecovery struct {
    dkgClient     DKGClient
    kms           KMSBackend
    auditLog      AuditLogger
}

// ReEnrollNode performs DKG re-enrollment for a node with complete share loss
func (cslr *CompleteShareLossRecovery) ReEnrollNode(
    ctx context.Context,
    nodeID [32]byte,
    groupID [32]byte,
    attestation []byte,
) (*ReEnrollmentResult, error) {
    // Step 1: Verify node identity via TPM attestation
    if err := cslr.verifyNodeIdentity(ctx, nodeID, attestation); err != nil {
        return nil, ErrIdentityVerificationFailed{Cause: err}
    }

    // Step 2: Request re-enrollment approval from pool
    approvalReq := &ReEnrollmentApprovalRequest{
        NodeID:      nodeID,
        GroupID:     groupID,
        Reason:      "complete_share_loss",
        Attestation: attestation,
        RequestedAt: time.Now(),
    }

    approval, err := cslr.dkgClient.RequestReEnrollmentApproval(ctx, approvalReq)
    if err != nil {
        return nil, ErrReEnrollmentApprovalFailed{Cause: err}
    }

    // Step 3: Wait for quorum approval (majority of existing pool members)
    if err := cslr.waitForApprovalQuorum(ctx, approval.ApprovalID); err != nil {
        return nil, ErrApprovalQuorumTimeout{Cause: err}
    }

    // Step 4: Participate in refresh DKG (node receives new share)
    refreshSession, err := cslr.dkgClient.JoinRefreshSession(ctx, approval.RefreshSessionID)
    if err != nil {
        return nil, ErrRefreshSessionJoinFailed{Cause: err}
    }

    // Step 5: Complete DKG and receive new share
    newShare, err := cslr.dkgClient.CompleteRefreshDKG(ctx, refreshSession)
    if err != nil {
        return nil, ErrRefreshDKGFailed{Cause: err}
    }

    // Step 6: Store new share securely
    shareID, err := cslr.kms.StoreNewShare(ctx, newShare, groupID)
    if err != nil {
        return nil, ErrShareStorageFailed{Cause: err}
    }

    // Step 7: Create backups for new share
    if err := cslr.createInitialBackups(ctx, shareID, nodeID, groupID); err != nil {
        // Log but don't fail - share is stored, backups can be retried
        cslr.auditLog.LogBackupFailure(ctx, shareID, err)
    }

    // Audit log
    cslr.auditLog.LogReEnrollment(ctx, nodeID, groupID, shareID)

    return &ReEnrollmentResult{
        Success:      true,
        NewShareID:   shareID,
        NewVersion:   newShare.Version,
        EnrolledAt:   time.Now(),
    }, nil
}

// ReEnrollmentResult contains the outcome of re-enrollment
type ReEnrollmentResult struct {
    Success    bool
    NewShareID [32]byte
    NewVersion uint32
    EnrolledAt time.Time
}
```

#### Disaster Recovery (Regional Failure)

```go
// RegionalDisasterRecovery handles recovery from regional failures
type RegionalDisasterRecovery struct {
    backupManager     *ShareBackupManager
    coldStorageClient ColdStorageClient
    approvalService   ApprovalService
    dkgClient         DKGClient
    auditLog          AuditLogger
}

// DisasterRecoveryRequest initiates regional disaster recovery
type DisasterRecoveryRequest struct {
    AffectedRegion    string
    AffectedNodes     [][32]byte
    AffectedGroups    [][32]byte
    IncidentID        string
    RequestedBy       string
    Approvers         []string
}

// InitiateRegionalRecovery starts the disaster recovery process
func (rdr *RegionalDisasterRecovery) InitiateRegionalRecovery(
    ctx context.Context,
    request DisasterRecoveryRequest,
) (*DisasterRecoveryStatus, error) {
    status := &DisasterRecoveryStatus{
        IncidentID:      request.IncidentID,
        StartedAt:       time.Now(),
        Phase:           DRPhaseInitiated,
        NodesRecovered:  make(map[[32]byte]NodeRecoveryStatus),
    }

    // Step 1: Verify multi-party authorization
    if err := rdr.verifyDisasterRecoveryAuth(ctx, request); err != nil {
        return nil, ErrDRAuthorizationFailed{Cause: err}
    }

    // Step 2: Retrieve cold storage backups
    status.Phase = DRPhaseRetrievingBackups
    for _, nodeID := range request.AffectedNodes {
        backups, err := rdr.retrieveColdStorageBackups(ctx, nodeID, request.AffectedGroups)
        if err != nil {
            status.NodesRecovered[nodeID] = NodeRecoveryStatus{
                Status: "backup_retrieval_failed",
                Error:  err.Error(),
            }
            continue
        }
        status.NodesRecovered[nodeID] = NodeRecoveryStatus{
            Status:  "backups_retrieved",
            Backups: backups,
        }
    }

    // Step 3: Reconstruct Shamir-split keys
    status.Phase = DRPhaseReconstructingKeys
    for nodeID, nodeStatus := range status.NodesRecovered {
        if nodeStatus.Status != "backups_retrieved" {
            continue
        }

        recoveredShares, err := rdr.reconstructShamirShares(ctx, nodeStatus.Backups)
        if err != nil {
            nodeStatus.Status = "shamir_reconstruction_failed"
            nodeStatus.Error = err.Error()
            status.NodesRecovered[nodeID] = nodeStatus
            continue
        }

        nodeStatus.RecoveredShares = recoveredShares
        nodeStatus.Status = "shares_reconstructed"
        status.NodesRecovered[nodeID] = nodeStatus
    }

    // Step 4: Restore shares to replacement infrastructure
    status.Phase = DRPhaseRestoringShares
    for nodeID, nodeStatus := range status.NodesRecovered {
        if nodeStatus.Status != "shares_reconstructed" {
            continue
        }

        if err := rdr.restoreSharesInNewRegion(ctx, nodeID, nodeStatus.RecoveredShares); err != nil {
            nodeStatus.Status = "share_restoration_failed"
            nodeStatus.Error = err.Error()
        } else {
            nodeStatus.Status = "shares_restored"
        }
        status.NodesRecovered[nodeID] = nodeStatus
    }

    // Step 5: Verify pool quorum after recovery
    status.Phase = DRPhaseVerifyingQuorum
    for _, groupID := range request.AffectedGroups {
        quorumStatus, err := rdr.verifyPoolQuorum(ctx, groupID)
        if err != nil {
            status.QuorumIssues = append(status.QuorumIssues, QuorumIssue{
                GroupID: groupID,
                Error:   err.Error(),
            })
        } else if !quorumStatus.HasQuorum {
            // Need to re-enroll additional nodes
            status.QuorumIssues = append(status.QuorumIssues, QuorumIssue{
                GroupID:        groupID,
                NodesNeeded:    quorumStatus.NodesNeeded,
                ReEnrollmentRequired: true,
            })
        }
    }

    // Step 6: Initiate re-enrollment for nodes that couldn't be recovered
    status.Phase = DRPhaseReEnrolling
    for nodeID, nodeStatus := range status.NodesRecovered {
        if nodeStatus.Status != "shares_restored" {
            // Attempt DKG re-enrollment
            if err := rdr.initiateEmergencyReEnrollment(ctx, nodeID, request.AffectedGroups); err != nil {
                nodeStatus.Status = "reenrollment_failed"
                nodeStatus.Error = err.Error()
            } else {
                nodeStatus.Status = "reenrollment_initiated"
            }
            status.NodesRecovered[nodeID] = nodeStatus
        }
    }

    status.Phase = DRPhaseComplete
    status.CompletedAt = time.Now()

    // Audit log
    rdr.auditLog.LogDisasterRecovery(ctx, status)

    return status, nil
}

// DisasterRecoveryStatus tracks DR progress
type DisasterRecoveryStatus struct {
    IncidentID     string
    StartedAt      time.Time
    CompletedAt    time.Time
    Phase          DRPhase
    NodesRecovered map[[32]byte]NodeRecoveryStatus
    QuorumIssues   []QuorumIssue
}

// DRPhase indicates current disaster recovery phase
type DRPhase uint8

const (
    DRPhaseInitiated         DRPhase = iota
    DRPhaseRetrievingBackups
    DRPhaseReconstructingKeys
    DRPhaseRestoringShares
    DRPhaseVerifyingQuorum
    DRPhaseReEnrolling
    DRPhaseComplete
)

// NodeRecoveryStatus tracks individual node recovery
type NodeRecoveryStatus struct {
    Status          string
    Error           string
    Backups         []ColdStorageBackup
    RecoveredShares [][]byte
}

// QuorumIssue indicates a pool with quorum problems
type QuorumIssue struct {
    GroupID              [32]byte
    NodesNeeded          int
    Error                string
    ReEnrollmentRequired bool
}
```

---

## Security Considerations

### Share Confidentiality During Transfer

```go
// ShareTransportSecurity handles encrypted share transfer
type ShareTransportSecurity struct {
    tlsConfig     *tls.Config
    noiseProtocol NoiseProtocol
    auditLog      AuditLogger
}

// TransportEncryption defines encryption layers for share transfer
type TransportEncryption struct {
    // Layer 1: TLS 1.3 with mTLS
    TLSVersion     uint16         // tls.VersionTLS13
    ClientCertRequired bool       // true - mutual TLS

    // Layer 2: Noise protocol (inside TLS)
    NoisePattern   string         // "XX" pattern for mutual auth
    NoiseCipher    string         // "ChaChaPoly"

    // Layer 3: Share-specific encryption
    ShareEncryption string        // "AES-256-GCM"
    EphemeralKeys  bool           // true - fresh keys per transfer
}

// SecureShareTransfer wraps a share for encrypted transfer
func (sts *ShareTransportSecurity) SecureShareTransfer(
    ctx context.Context,
    share *EncryptedBlob,
    recipientPubKey []byte,
) (*TransferPackage, error) {
    // Generate ephemeral key pair for this transfer
    ephemeralPriv, ephemeralPub, err := sts.generateEphemeralKeyPair()
    if err != nil {
        return nil, err
    }
    defer secureWipe(ephemeralPriv)

    // Derive shared secret using X25519
    sharedSecret, err := x25519.X25519(ephemeralPriv, recipientPubKey)
    if err != nil {
        return nil, err
    }
    defer secureWipe(sharedSecret)

    // Derive transport key using HKDF
    transportKey := hkdf.Extract(sha256.New, sharedSecret, []byte("frost-share-transport"))

    // Encrypt share blob with transport key
    encryptedTransport, err := sts.encryptWithTransportKey(share, transportKey)
    if err != nil {
        return nil, err
    }

    return &TransferPackage{
        EphemeralPublicKey: ephemeralPub,
        EncryptedShare:     encryptedTransport,
        Timestamp:          time.Now(),
        Signature:          sts.signTransferPackage(encryptedTransport),
    }, nil
}

// TransferPackage contains encrypted share for network transfer
type TransferPackage struct {
    EphemeralPublicKey []byte
    EncryptedShare     []byte
    Timestamp          time.Time
    Signature          []byte
}
```

### Anti-Extraction Protections

```go
// AntiExtractionPolicy defines protections against share extraction
type AntiExtractionPolicy struct {
    // Rate limiting
    MaxAccessPerMinute   int           // 10 accesses per minute
    MaxAccessPerHour     int           // 100 accesses per hour

    // Anomaly detection
    AnomalyThreshold     float64       // 0.95 confidence for block
    BaselineWindow       time.Duration // 24 hours

    // Hardware binding
    TPMBindingRequired   bool          // true for identity shares
    PCRPolicyEnforced    bool          // true - PCR-bound access

    // Memory protection
    SecureWipeOnAccess   bool          // true - wipe after use
    MaxMemoryResidence   time.Duration // 30 seconds max in memory

    // Access logging
    DetailedAuditLog     bool          // true - log all accesses
}

// AntiExtractionMonitor monitors for extraction attempts
type AntiExtractionMonitor struct {
    policy      AntiExtractionPolicy
    rateLimiter *RateLimiter
    anomalyDet  *AnomalyDetector
    auditLog    AuditLogger
}

// CheckAccessAttempt validates a share access against policy
func (aem *AntiExtractionMonitor) CheckAccessAttempt(
    ctx context.Context,
    shareID [32]byte,
    accessor [32]byte,
    metadata AccessMetadata,
) error {
    // Check rate limits
    if !aem.rateLimiter.AllowAccess(shareID, accessor) {
        aem.auditLog.LogRateLimitViolation(ctx, shareID, accessor)
        return ErrRateLimitExceeded{ShareID: shareID}
    }

    // Check for anomalous behavior
    anomalyScore := aem.anomalyDet.Score(accessor, metadata)
    if anomalyScore > aem.policy.AnomalyThreshold {
        aem.auditLog.LogAnomalyDetected(ctx, shareID, accessor, anomalyScore)
        return ErrAnomalousAccessPattern{Score: anomalyScore}
    }

    // Verify TPM binding if required
    if aem.policy.TPMBindingRequired {
        if err := aem.verifyTPMBinding(ctx, accessor, metadata.TPMQuote); err != nil {
            aem.auditLog.LogTPMBindingFailure(ctx, shareID, accessor)
            return ErrTPMBindingFailed{Cause: err}
        }
    }

    return nil
}

// AccessMetadata contains context for access validation
type AccessMetadata struct {
    RequestTime    time.Time
    SourceIP       string
    TPMQuote       []byte
    Purpose        string           // "signing", "backup", "recovery"
    SigningRequest *FROSTSigningRequest
}
```

### Key Hierarchy Security

```
+------------------------------------------------------------------+
|                      Key Hierarchy (Defense in Depth)             |
+------------------------------------------------------------------+
|                                                                    |
|  Level 0: Hardware Root of Trust                                  |
|  ├── TPM Endorsement Key (EK) - Manufacturer-provisioned          |
|  ├── TPM Storage Root Key (SRK) - Platform master                 |
|  └── HSM Master Key - External hardware root                      |
|                                                                    |
|  Level 1: Key Encryption Keys (KEKs)                              |
|  ├── TPM-sealed KEK - For local share encryption                  |
|  ├── HSM KEK - For backup encryption                              |
|  └── Cloud KMS KEK - For cloud-native deployments                 |
|                                                                    |
|  Level 2: Data Encryption Keys (DEKs)                             |
|  ├── Share-specific DEK - Unique per share                        |
|  ├── Version-specific DEK - Changes on rotation                   |
|  └── Backup-specific DEK - For backup encryption                  |
|                                                                    |
|  Level 3: Protected Data                                          |
|  ├── FROST Secret Share - Encrypted with DEK                      |
|  ├── FROST Nonces - TPM-sealed, PCR-bound                         |
|  └── Share Metadata - Encrypted with separate DEK                 |
|                                                                    |
|  Security Properties:                                             |
|  - Compromise of Level N does not expose Level N-1 keys           |
|  - DEKs are rotated frequently (share rotation)                   |
|  - KEKs are long-lived but hardware-protected                     |
|  - Hardware roots are immutable and tamper-evident                |
|                                                                    |
+------------------------------------------------------------------+
```

```go
// KeyHierarchyManager enforces the key hierarchy
type KeyHierarchyManager struct {
    tpm         TPMInterface
    hsm         HSMInterface
    cloudKMS    CloudKMSInterface
    auditLog    AuditLogger
}

// KeyLevel represents position in the hierarchy
type KeyLevel uint8

const (
    KeyLevelHardwareRoot KeyLevel = 0  // TPM EK, SRK, HSM Master
    KeyLevelKEK          KeyLevel = 1  // Key Encryption Keys
    KeyLevelDEK          KeyLevel = 2  // Data Encryption Keys
    KeyLevelData         KeyLevel = 3  // Protected data
)

// KeyHierarchyPolicy defines key management rules
type KeyHierarchyPolicy struct {
    // KEK policies
    KEKRotationInterval   time.Duration  // 365 days
    KEKBackupRequired     bool           // true
    KEKMinKeySize         int            // 256 bits

    // DEK policies
    DEKRotationInterval   time.Duration  // 30 days (share rotation)
    DEKPerShareIsolation  bool           // true - unique DEK per share
    DEKBackupRequired     bool           // true

    // Hierarchy enforcement
    StrictHierarchy       bool           // true - Level N cannot access N-1
    CrossLevelAudit       bool           // true - log all level crossings
}

// DeriveChildKey derives a child key within hierarchy constraints
func (khm *KeyHierarchyManager) DeriveChildKey(
    ctx context.Context,
    parentLevel KeyLevel,
    childLevel KeyLevel,
    parentKeyRef string,
    purpose string,
) (*DerivedKey, error) {
    // Enforce hierarchy: can only derive to lower levels
    if childLevel <= parentLevel {
        return nil, ErrHierarchyViolation{
            ParentLevel: parentLevel,
            ChildLevel:  childLevel,
        }
    }

    // Derive child key based on parent level
    var childKey []byte
    var err error

    switch parentLevel {
    case KeyLevelHardwareRoot:
        childKey, err = khm.deriveFromHardwareRoot(ctx, parentKeyRef, purpose)
    case KeyLevelKEK:
        childKey, err = khm.deriveFromKEK(ctx, parentKeyRef, purpose)
    default:
        return nil, ErrInvalidParentLevel{Level: parentLevel}
    }

    if err != nil {
        return nil, err
    }

    // Audit log
    khm.auditLog.LogKeyDerivation(ctx, parentLevel, childLevel, purpose)

    return &DerivedKey{
        Level:   childLevel,
        Key:     childKey,
        Purpose: purpose,
    }, nil
}

// DerivedKey represents a key in the hierarchy
type DerivedKey struct {
    Level   KeyLevel
    Key     []byte
    Purpose string
}
```

---

## Error Types

```go
// KMS-FROST integration errors

type ErrDEKGenerationFailed struct {
    Cause error
}

func (e ErrDEKGenerationFailed) Error() string {
    return fmt.Sprintf("DEK generation failed: %v", e.Cause)
}

type ErrShareEncryptionFailed struct {
    Cause error
}

func (e ErrShareEncryptionFailed) Error() string {
    return fmt.Sprintf("share encryption failed: %v", e.Cause)
}

type ErrKEKAccessFailed struct {
    Cause error
}

func (e ErrKEKAccessFailed) Error() string {
    return fmt.Sprintf("KEK access failed: %v", e.Cause)
}

type ErrDEKEncryptionFailed struct {
    Cause error
}

func (e ErrDEKEncryptionFailed) Error() string {
    return fmt.Sprintf("DEK encryption failed: %v", e.Cause)
}

type ErrTPMSealingFailed struct {
    Cause error
}

func (e ErrTPMSealingFailed) Error() string {
    return fmt.Sprintf("TPM sealing failed: %v", e.Cause)
}

type ErrShareStorageFailed struct {
    Cause error
}

func (e ErrShareStorageFailed) Error() string {
    return fmt.Sprintf("share storage failed: %v", e.Cause)
}

type ErrShareNotFound struct {
    ShareID [32]byte
    Cause   error
}

func (e ErrShareNotFound) Error() string {
    return fmt.Sprintf("share %x not found: %v", e.ShareID[:8], e.Cause)
}

type ErrShareNotActive struct {
    ShareID [32]byte
    Status  ShareStatus
}

func (e ErrShareNotActive) Error() string {
    return fmt.Sprintf("share %x is not active (status: %d)", e.ShareID[:8], e.Status)
}

type ErrShareExpired struct {
    ShareID   [32]byte
    ExpiredAt time.Time
}

func (e ErrShareExpired) Error() string {
    return fmt.Sprintf("share %x expired at %v", e.ShareID[:8], e.ExpiredAt)
}

type ErrPCRPolicyViolation struct {
    PCRIndex int
    Expected []byte
    Actual   []byte
}

func (e ErrPCRPolicyViolation) Error() string {
    return fmt.Sprintf("PCR %d policy violation: expected %x, got %x",
        e.PCRIndex, e.Expected[:8], e.Actual[:8])
}

type ErrShareAccessRateLimited struct {
    ShareID [32]byte
}

func (e ErrShareAccessRateLimited) Error() string {
    return fmt.Sprintf("share %x access rate limited", e.ShareID[:8])
}

type ErrAnomalousAccessPattern struct {
    Score float64
}

func (e ErrAnomalousAccessPattern) Error() string {
    return fmt.Sprintf("anomalous access pattern detected (score: %.2f)", e.Score)
}

type ErrHierarchyViolation struct {
    ParentLevel KeyLevel
    ChildLevel  KeyLevel
}

func (e ErrHierarchyViolation) Error() string {
    return fmt.Sprintf("key hierarchy violation: cannot derive level %d from level %d",
        e.ChildLevel, e.ParentLevel)
}

type ErrNoActiveShareVersion struct {
    GroupID [32]byte
}

func (e ErrNoActiveShareVersion) Error() string {
    return fmt.Sprintf("no active share version for group %x", e.GroupID[:8])
}

type ErrRecoveryApprovalRequired struct {
    Cause error
}

func (e ErrRecoveryApprovalRequired) Error() string {
    return fmt.Sprintf("cold storage recovery requires multi-party approval: %v", e.Cause)
}

type ErrNVRAMFull struct{}

func (e ErrNVRAMFull) Error() string {
    return "TPM NVRAM storage is full"
}
```

---

## CLI Reference

### Share Management Commands

```bash
# View share status
platformctl frost shares list --group "ed25519-ca"
platformctl frost shares status --share-id <id>

# Manual backup operations
platformctl frost backup create --share-id <id> --tiers "tpm,hsm,cold"
platformctl frost backup list --node-id <id>
platformctl frost backup verify --backup-id <id>

# Recovery operations
platformctl frost recover --share-id <id> --source hsm
platformctl frost recover --share-id <id> --source cold --approvers "admin1,admin2,admin3"
platformctl frost reenroll --group "ed25519-ca" --reason "lost_share"

# Rotation management
platformctl frost rotate --group "ed25519-ca" --reason "scheduled"
platformctl frost rotate status --group "ed25519-ca"
platformctl frost rotate history --group "ed25519-ca" --limit 10

# KMS backend management
platformctl kms status
platformctl kms backends list
platformctl kms keys list --level kek
platformctl kms keys rotate --key-id <id>

# TPM operations
platformctl tpm shares list
platformctl tpm shares unseal --share-id <id>
platformctl tpm nvram status
platformctl tpm pcr read --indices "0,2,7"
```

---

## Related Documentation

- [04-cryptographic-protocols.md](04-cryptographic-protocols.md) - FROST and DKG protocol details
- [05-certificate-authority.md](05-certificate-authority.md) - CA architecture and FROST pools
- [11-operations.md](11-operations.md) - Operational procedures and disaster recovery
- [03-security-trust.md](03-security-trust.md) - Trust model and TPM attestation
