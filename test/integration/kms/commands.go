// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package kms

import (
	"context"
	"time"
)

// KMSCommands defines the central command set for KMS integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Socket) implements this interface.
// Tests are written once against this interface and run against all protocols.
type KMSCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Key Management Commands (platformctl kms key ...)
	KeyGenerate(ctx context.Context, opts KeyGenerateOptions) (*KeyGenerateResult, error)
	KeyGet(ctx context.Context, keyID string, version uint64) (*KeyGetResult, error)
	KeyList(ctx context.Context, opts KeyListOptions) (*KeyListResult, error)
	KeyDelete(ctx context.Context, keyID string, opts KeyDeleteOptions) (*KeyDeleteResult, error)
	KeyRotate(ctx context.Context, keyID string, retainOldVersion bool) (*KeyRotateResult, error)
	KeyVersions(ctx context.Context, keyID string, opts KeyVersionsOptions) (*KeyVersionsResult, error)
	KeyStatus(ctx context.Context, keyID string, version uint64, enabled bool) (*KeyStatusResult, error)
	KeyRevoke(ctx context.Context, keyID string, reason string) (*KeyRevokeResult, error)
	KeyMetadata(ctx context.Context, keyID string) (*KeyMetadataResult, error)
	KeyMetadataUpdate(ctx context.Context, keyID string, opts KeyMetadataUpdateOptions) (*KeyMetadataUpdateResult, error)
	KeyPolicy(ctx context.Context, keyID string) (*KeyPolicyResult, error)
	KeyPolicySet(ctx context.Context, keyID string, opts KeyPolicySetOptions) (*KeyPolicySetResult, error)
	KeyAlgorithms(ctx context.Context) (*KeyAlgorithmsResult, error)

	// Crypto Commands (platformctl kms crypto ...)
	CryptoEncrypt(ctx context.Context, opts CryptoEncryptOptions) (*CryptoEncryptResult, error)
	CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error)
	CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error)
	CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error)
	CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error)
	CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error)
	CryptoVerifyHMAC(ctx context.Context, opts CryptoVerifyHMACOptions) (*CryptoVerifyHMACResult, error)
	CryptoRandom(ctx context.Context, numBytes int) (*CryptoRandomResult, error)

	// DEK Commands (platformctl kms dek ...)
	DEKCreate(ctx context.Context, opts DEKCreateOptions) (*DEKCreateResult, error)
	DEKGet(ctx context.Context, path string) (*DEKGetResult, error)
	DEKList(ctx context.Context, opts DEKListOptions) (*DEKListResult, error)
	DEKDelete(ctx context.Context, path string, opts DEKDeleteOptions) (*DEKDeleteResult, error)
	DEKRotate(ctx context.Context, path string, background bool) (*DEKRotateResult, error)
	DEKStatus(ctx context.Context, path string) (*DEKStatusResult, error)

	// Secrets Commands (platformctl kms secrets ...)
	SecretsStore(ctx context.Context, opts SecretsStoreOptions) (*SecretsStoreResult, error)
	SecretsGet(ctx context.Context, name string) (*SecretsGetResult, error)
	SecretsList(ctx context.Context, opts SecretsListOptions) (*SecretsListResult, error)
	SecretsDelete(ctx context.Context, name string, permanent bool) (*SecretsDeleteResult, error)
	SecretsRotate(ctx context.Context, opts SecretsRotateOptions) (*SecretsRotateResult, error)
	SecretsVersions(ctx context.Context, name string, opts SecretsVersionsOptions) (*SecretsVersionsResult, error)
	SecretsVersion(ctx context.Context, name string, version uint64) (*SecretsVersionResult, error)
	SecretsRollback(ctx context.Context, name string, targetVersion uint64) (*SecretsRollbackResult, error)
	SecretsStatus(ctx context.Context, name string, enabled bool) (*SecretsStatusResult, error)
}

// Key Management Options and Results

// KeyGenerateOptions contains options for generating a new key.
type KeyGenerateOptions struct {
	KeyID              string
	Algorithm          string
	Purpose            string
	Exportable         bool
	DeletionProtection bool
	Name               string
	Description        string
	Owner              string
}

// KeyGenerateResult contains the result of a key generation operation.
type KeyGenerateResult struct {
	KeyID              string
	Version            uint64
	Algorithm          string
	Status             string
	CreatedAt          time.Time
	Name               string
	Description        string
	Exportable         bool
	DeletionProtection bool
}

// KeyGetResult contains the result of a key retrieval operation.
type KeyGetResult struct {
	KeyID              string
	Version            uint64
	Algorithm          string
	Status             string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	LastUsedAt         time.Time
	Name               string
	Description        string
	Owner              string
	Exportable         bool
	DeletionProtection bool
	Usage              []string
}

// KeyListOptions contains options for listing keys.
type KeyListOptions struct {
	Limit  int32
	Cursor string
}

// KeyListResult contains the result of a key list operation.
type KeyListResult struct {
	Keys       []KeySummary
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// KeySummary contains summary information about a key.
type KeySummary struct {
	KeyID     string
	Version   uint64
	Algorithm string
	Status    string
	CreatedAt time.Time
}

// KeyDeleteOptions contains options for deleting a key.
type KeyDeleteOptions struct {
	PendingWindowDays int32
	Force             bool
}

// KeyDeleteResult contains the result of a key deletion operation.
type KeyDeleteResult struct {
	KeyID        string
	Status       string
	DeletionDate time.Time
}

// KeyRotateResult contains the result of a key rotation operation.
type KeyRotateResult struct {
	KeyID      string
	OldVersion uint64
	NewVersion uint64
	RotatedAt  time.Time
}

// KeyVersionsOptions contains options for listing key versions.
type KeyVersionsOptions struct {
	Limit  int32
	Cursor string
}

// KeyVersionsResult contains the result of a key versions list operation.
type KeyVersionsResult struct {
	KeyID      string
	Versions   []KeyVersionInfo
	HasMore    bool
	NextCursor string
}

// KeyVersionInfo contains information about a specific key version.
type KeyVersionInfo struct {
	Version    uint64
	Algorithm  string
	Status     string
	CreatedAt  time.Time
	DisabledAt time.Time
}

// KeyStatusResult contains the result of a key status update operation.
type KeyStatusResult struct {
	KeyID     string
	Version   uint64
	Status    string
	UpdatedAt time.Time
}

// KeyRevokeResult contains the result of a key revocation operation.
type KeyRevokeResult struct {
	KeyID     string
	Status    string
	RevokedAt time.Time
}

// KeyMetadataResult contains the result of a key metadata retrieval operation.
type KeyMetadataResult struct {
	KeyID              string
	Name               string
	Description        string
	Algorithm          string
	Status             string
	Version            uint64
	Exportable         bool
	DeletionProtection bool
	Usage              []string
	Owner              string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	LastUsedAt         time.Time
	Tags               map[string]string
	RotationPolicy     *RotationPolicy
}

// RotationPolicy contains key rotation policy information.
type RotationPolicy struct {
	Enabled         bool
	IntervalSeconds int64
	NextRotation    time.Time
	RetainVersions  int32
}

// KeyMetadataUpdateOptions contains options for updating key metadata.
type KeyMetadataUpdateOptions struct {
	Name        string
	Description string
	Tags        map[string]string
	RemoveTags  []string
}

// KeyMetadataUpdateResult contains the result of a key metadata update operation.
type KeyMetadataUpdateResult struct {
	KeyID     string
	Name      string
	UpdatedAt time.Time
	Tags      map[string]string
}

// KeyPolicyResult contains the result of a key policy retrieval operation.
type KeyPolicyResult struct {
	KeyID             string
	Version           int32
	AllowedOperations []string
	AllowedPrincipals []string
	DeniedPrincipals  []string
	ExpiresAt         time.Time
	RotationRequired  bool
	MaxUsageCount     uint64
	RequireMFA        bool
	UpdatedAt         time.Time
}

// KeyPolicySetOptions contains options for setting a key policy.
type KeyPolicySetOptions struct {
	Operations       []string
	AllowPrincipals  []string
	DenyPrincipals   []string
	ExpiresIn        string
	RotationRequired bool
	MaxUsageCount    uint64
	RequireMFA       bool
}

// KeyPolicySetResult contains the result of a key policy set operation.
type KeyPolicySetResult struct {
	KeyID         string
	PolicyVersion int32
	UpdatedAt     time.Time
}

// KeyAlgorithmsResult contains the result of a supported algorithms query.
type KeyAlgorithmsResult struct {
	Algorithms []string
}

// Crypto Options and Results

// CryptoEncryptOptions contains options for encryption.
type CryptoEncryptOptions struct {
	KeyID     string
	Plaintext []byte
	Context   []byte
	Nonce     []byte
}

// CryptoEncryptResult contains the result of an encryption operation.
type CryptoEncryptResult struct {
	KeyID      string
	KeyVersion uint64
	Ciphertext []byte
	Nonce      []byte
	Timestamp  time.Time
}

// CryptoDecryptOptions contains options for decryption.
type CryptoDecryptOptions struct {
	KeyID      string
	Ciphertext []byte
	Context    []byte
	Nonce      []byte
	KeyVersion uint64
}

// CryptoDecryptResult contains the result of a decryption operation.
type CryptoDecryptResult struct {
	KeyID      string
	KeyVersion uint64
	Plaintext  []byte
	Timestamp  time.Time
}

// CryptoSignOptions contains options for signing.
type CryptoSignOptions struct {
	KeyID         string
	Message       []byte
	HashAlgorithm string
}

// CryptoSignResult contains the result of a signing operation.
type CryptoSignResult struct {
	KeyID         string
	KeyVersion    uint64
	Signature     []byte
	HashAlgorithm string
	Timestamp     time.Time
}

// CryptoVerifyOptions contains options for signature verification.
type CryptoVerifyOptions struct {
	KeyID         string
	Message       []byte
	Signature     []byte
	HashAlgorithm string
	KeyVersion    uint64
}

// CryptoVerifyResult contains the result of a signature verification operation.
type CryptoVerifyResult struct {
	KeyID      string
	KeyVersion uint64
	Valid      bool
	Timestamp  time.Time
}

// CryptoHashResult contains the result of a hash operation.
type CryptoHashResult struct {
	Algorithm string
	Hash      []byte
	Timestamp time.Time
}

// CryptoHMACOptions contains options for HMAC generation.
type CryptoHMACOptions struct {
	KeyID         string
	Message       []byte
	HashAlgorithm string
}

// CryptoHMACResult contains the result of an HMAC generation operation.
type CryptoHMACResult struct {
	KeyID         string
	KeyVersion    uint64
	HMAC          []byte
	HashAlgorithm string
	Timestamp     time.Time
}

// CryptoVerifyHMACOptions contains options for HMAC verification.
type CryptoVerifyHMACOptions struct {
	KeyID         string
	Message       []byte
	HMAC          []byte
	HashAlgorithm string
	KeyVersion    uint64
}

// CryptoVerifyHMACResult contains the result of an HMAC verification operation.
type CryptoVerifyHMACResult struct {
	KeyID      string
	KeyVersion uint64
	Valid      bool
	Timestamp  time.Time
}

// CryptoRandomResult contains the result of a random bytes generation operation.
type CryptoRandomResult struct {
	RandomBytes []byte
	Timestamp   time.Time
}

// DEK Options and Results

// DEKCreateOptions contains options for creating a DEK.
type DEKCreateOptions struct {
	Path           string
	Algorithm      string
	Description    string
	MaxOperations  uint64
	MaxBytes       uint64
	WarningPercent int32
}

// DEKCreateResult contains the result of a DEK creation operation.
type DEKCreateResult struct {
	Path        string
	Algorithm   string
	Version     uint64
	CreatedAt   time.Time
	Description string
}

// DEKGetResult contains the result of a DEK retrieval operation.
type DEKGetResult struct {
	Path           string
	Algorithm      string
	Version        uint64
	Status         string
	IsDefault      bool
	CreatedAt      time.Time
	RotatedAt      time.Time
	Description    string
	BackendType    string
	UsageCount     uint64
	BytesUsed      uint64
	MaxUsageCount  uint64
	MaxBytesUsed   uint64
	WarningPercent int32
}

// DEKListOptions contains options for listing DEKs.
type DEKListOptions struct {
	Prefix    string
	Recursive bool
	Limit     int32
	Cursor    string
}

// DEKListResult contains the result of a DEK list operation.
type DEKListResult struct {
	DEKs       []DEKSummary
	HasMore    bool
	NextCursor string
}

// DEKSummary contains summary information about a DEK.
type DEKSummary struct {
	Path      string
	Algorithm string
	Version   uint64
	Status    string
	IsDefault bool
	CreatedAt time.Time
}

// DEKDeleteOptions contains options for deleting a DEK.
type DEKDeleteOptions struct {
	Force     bool
	MigrateTo string
}

// DEKDeleteResult contains the result of a DEK deletion operation.
type DEKDeleteResult struct {
	Path    string
	Deleted bool
}

// DEKRotateResult contains the result of a DEK rotation operation.
type DEKRotateResult struct {
	Path       string
	OldVersion uint64
	NewVersion uint64
}

// DEKStatusResult contains the result of a DEK status retrieval operation.
type DEKStatusResult struct {
	Path                   string
	Algorithm              string
	Version                uint64
	Status                 string
	IsDefault              bool
	CreatedAt              time.Time
	RotatedAt              time.Time
	Description            string
	BackendType            string
	UsageCount             uint64
	BytesUsed              uint64
	MaxUsageCount          uint64
	MaxBytesUsed           uint64
	WarningPercent         int32
	ReencryptionInProgress bool
	ProcessedKeys          int64
	TotalKeys              int64
	FailedKeys             int64
	ReencryptionStartedAt  time.Time
	EstimatedCompletion    time.Time
}

// Secrets Options and Results

// SecretsStoreOptions contains options for storing a secret.
type SecretsStoreOptions struct {
	Name        string
	Data        []byte
	Description string
	TenantID    string
	KeyID       string
	Algorithm   string
}

// SecretsStoreResult contains the result of a secret store operation.
type SecretsStoreResult struct {
	SecretID  string
	Version   uint64
	Timestamp time.Time
}

// SecretsGetResult contains the result of a secret retrieval operation.
type SecretsGetResult struct {
	SecretID      string
	Version       uint64
	Data          []byte
	Metadata      map[string]string
	Algorithm     string
	KeyIdentifier string
	CreatedAt     time.Time
	Timestamp     time.Time
}

// SecretsListOptions contains options for listing secrets.
type SecretsListOptions struct {
	Limit  int32
	Cursor string
}

// SecretsListResult contains the result of a secrets list operation.
type SecretsListResult struct {
	Secrets    []SecretSummary
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// SecretSummary contains summary information about a secret.
type SecretSummary struct {
	Name           string
	CurrentVersion uint64
	Description    string
	Owner          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// SecretsDeleteResult contains the result of a secret deletion operation.
type SecretsDeleteResult struct {
	SecretID  string
	Deleted   bool
	Timestamp time.Time
}

// SecretsRotateOptions contains options for rotating a secret.
type SecretsRotateOptions struct {
	Name      string
	NewData   []byte
	TenantID  string
	KeyID     string
	Algorithm string
}

// SecretsRotateResult contains the result of a secret rotation operation.
type SecretsRotateResult struct {
	SecretID   string
	OldVersion uint64
	NewVersion uint64
	Timestamp  time.Time
}

// SecretsVersionsOptions contains options for listing secret versions.
type SecretsVersionsOptions struct {
	Limit  int32
	Cursor string
}

// SecretsVersionsResult contains the result of a secret versions list operation.
type SecretsVersionsResult struct {
	SecretID   string
	Versions   []SecretVersionInfo
	HasMore    bool
	NextCursor string
}

// SecretVersionInfo contains information about a specific secret version.
type SecretVersionInfo struct {
	Version   uint64
	CreatedAt time.Time
	CreatedBy string
	ExpiresAt time.Time
}

// SecretsVersionResult contains the result of retrieving a specific secret version.
type SecretsVersionResult struct {
	SecretID  string
	Version   uint64
	Data      []byte
	Metadata  map[string]string
	CreatedAt time.Time
	CreatedBy string
	ExpiresAt time.Time
	Timestamp time.Time
}

// SecretsRollbackResult contains the result of a secret rollback operation.
type SecretsRollbackResult struct {
	SecretID   string
	NewVersion uint64
	Timestamp  time.Time
}

// SecretsStatusResult contains the result of a secret status update operation.
type SecretsStatusResult struct {
	SecretID  string
	Status    string
	Timestamp time.Time
}
