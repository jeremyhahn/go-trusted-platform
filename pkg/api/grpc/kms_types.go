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

package grpc

import "context"

// KMSService defines the interface for KMS operations.
// This interface is implemented by KMS service providers and used by the gRPC service.
type KMSService interface {
	// Key management
	GenerateKey(ctx context.Context, req *KMSGenerateKeyRequest) (*KMSGenerateKeyResponse, error)
	ImportKey(ctx context.Context, req *KMSImportKeyRequest) (*KMSImportKeyResponse, error)
	GetKey(ctx context.Context, req *KMSGetKeyRequest) (*KMSGetKeyResponse, error)
	ListKeys(ctx context.Context, req *KMSListKeysRequest) (*KMSListKeysResponse, error)
	DeleteKey(ctx context.Context, req *KMSDeleteKeyRequest) (*KMSDeleteKeyResponse, error)
	RotateKey(ctx context.Context, req *KMSRotateKeyRequest) (*KMSRotateKeyResponse, error)
	UpdateKeyStatus(ctx context.Context, req *KMSUpdateKeyStatusRequest) (*KMSUpdateKeyStatusResponse, error)
	ExportKey(ctx context.Context, req *KMSExportKeyRequest) (*KMSExportKeyResponse, error)
	GetKeyVersions(ctx context.Context, req *KMSGetKeyVersionsRequest) (*KMSGetKeyVersionsResponse, error)

	// Cryptographic operations
	Encrypt(ctx context.Context, req *KMSEncryptRequest) (*KMSEncryptResponse, error)
	Decrypt(ctx context.Context, req *KMSDecryptRequest) (*KMSDecryptResponse, error)
	BatchEncrypt(ctx context.Context, req *KMSBatchEncryptRequest) (*KMSBatchEncryptResponse, error)
	BatchDecrypt(ctx context.Context, req *KMSBatchDecryptRequest) (*KMSBatchDecryptResponse, error)
	Rewrap(ctx context.Context, req *KMSRewrapRequest) (*KMSRewrapResponse, error)
	Sign(ctx context.Context, req *KMSSignRequest) (*KMSSignResponse, error)
	Verify(ctx context.Context, req *KMSVerifyRequest) (*KMSVerifyResponse, error)
	Hash(ctx context.Context, req *KMSHashRequest) (*KMSHashResponse, error)
	HMAC(ctx context.Context, req *KMSHMACRequest) (*KMSHMACResponse, error)
	VerifyHMAC(ctx context.Context, req *KMSVerifyHMACRequest) (*KMSVerifyHMACResponse, error)
	GenerateRandom(ctx context.Context, req *KMSGenerateRandomRequest) (*KMSGenerateRandomResponse, error)

	// Backend status
	BackendStatus(ctx context.Context) (*KMSBackendStatusResponse, error)
}

// =============================================================================
// Key Specification Types
// =============================================================================

// KMSKeySpec defines key specification.
type KMSKeySpec struct {
	Algorithm          int32
	KeySize            int32
	Usage              []int32
	Exportable         bool
	DeletionProtection bool
}

// KMSKeyHandle represents a key handle.
type KMSKeyHandle struct {
	KeyID     string
	Version   uint64
	Algorithm int32
	Status    int32
	CreatedAt int64
}

// KMSKeyMetadata represents key metadata.
type KMSKeyMetadata struct {
	KeyID              string
	Name               string
	Description        string
	Algorithm          int32
	Status             int32
	Usage              []int32
	Version            uint64
	Exportable         bool
	DeletionProtection bool
	CreatedAt          int64
	UpdatedAt          int64
	LastUsedAt         int64
	Tags               map[string]string
	Owner              string
}

// KMSKeyVersionInfo represents key version info.
type KMSKeyVersionInfo struct {
	Version    uint64
	Status     int32
	Algorithm  int32
	CreatedAt  int64
	DisabledAt int64
}

// =============================================================================
// Key Management Request/Response Types
// =============================================================================

// KMSGenerateKeyRequest represents a key generation request.
type KMSGenerateKeyRequest struct {
	KeySpec     *KMSKeySpec
	Name        string
	Description string
	Tags        map[string]string
	Owner       string
}

// KMSGenerateKeyResponse represents a key generation response.
type KMSGenerateKeyResponse struct {
	Key       *KMSKeyHandle
	Metadata  *KMSKeyMetadata
	Timestamp int64
}

// KMSImportKeyRequest represents a key import request.
type KMSImportKeyRequest struct {
	KeyMaterial   []byte
	WrappingKeyID string
	KeySpec       *KMSKeySpec
	Name          string
	Description   string
	Tags          map[string]string
}

// KMSImportKeyResponse represents a key import response.
type KMSImportKeyResponse struct {
	Key       *KMSKeyHandle
	Metadata  *KMSKeyMetadata
	Timestamp int64
}

// KMSGetKeyRequest represents a get key request.
type KMSGetKeyRequest struct {
	KeyID   string
	Version uint64
}

// KMSGetKeyResponse represents a get key response.
type KMSGetKeyResponse struct {
	Key       *KMSKeyHandle
	Metadata  *KMSKeyMetadata
	Timestamp int64
}

// KMSListKeysRequest represents a list keys request.
type KMSListKeysRequest struct {
	Limit  int32
	Cursor string
	Filter map[string]string
}

// KMSListKeysResponse represents a list keys response.
type KMSListKeysResponse struct {
	Keys       []*KMSKeyHandle
	NextCursor string
	HasMore    bool
	TotalCount int32
	Timestamp  int64
}

// KMSDeleteKeyRequest represents a delete key request.
type KMSDeleteKeyRequest struct {
	KeyID             string
	PendingWindowDays int32
	Force             bool
}

// KMSDeleteKeyResponse represents a delete key response.
type KMSDeleteKeyResponse struct {
	KeyID        string
	Status       int32
	DeletionDate int64
	Timestamp    int64
}

// KMSRotateKeyRequest represents a rotate key request.
type KMSRotateKeyRequest struct {
	KeyID            string
	RetainOldVersion bool
}

// KMSRotateKeyResponse represents a rotate key response.
type KMSRotateKeyResponse struct {
	KeyID      string
	OldVersion uint64
	NewVersion uint64
	Timestamp  int64
}

// KMSUpdateKeyStatusRequest represents an update key status request.
type KMSUpdateKeyStatusRequest struct {
	KeyID   string
	Version uint64
	Status  int32
}

// KMSUpdateKeyStatusResponse represents an update key status response.
type KMSUpdateKeyStatusResponse struct {
	KeyID     string
	Version   uint64
	Status    int32
	Timestamp int64
}

// KMSExportKeyRequest represents an export key request.
type KMSExportKeyRequest struct {
	KeyID             string
	WrappingKeyID     string
	WrappingAlgorithm int32
	Format            int32
	Version           uint64
}

// KMSExportKeyResponse represents an export key response.
type KMSExportKeyResponse struct {
	KeyID             string
	Format            int32
	WrappingKeyID     string
	WrappingAlgorithm int32
	WrappedMaterial   []byte
	Version           uint64
	Timestamp         int64
}

// KMSGetKeyVersionsRequest represents a get key versions request.
type KMSGetKeyVersionsRequest struct {
	KeyID  string
	Limit  int32
	Cursor string
}

// KMSGetKeyVersionsResponse represents a get key versions response.
type KMSGetKeyVersionsResponse struct {
	KeyID      string
	Versions   []*KMSKeyVersionInfo
	NextCursor string
	HasMore    bool
	Timestamp  int64
}

// =============================================================================
// Cryptographic Operation Request/Response Types
// =============================================================================

// KMSEncryptRequest represents an encrypt request.
type KMSEncryptRequest struct {
	KeyID     string
	Plaintext []byte
	Context   []byte
	Nonce     []byte
}

// KMSEncryptResponse represents an encrypt response.
type KMSEncryptResponse struct {
	KeyID      string
	KeyVersion uint64
	Ciphertext []byte
	Nonce      []byte
	Timestamp  int64
}

// KMSDecryptRequest represents a decrypt request.
type KMSDecryptRequest struct {
	KeyID      string
	Ciphertext []byte
	Context    []byte
	Nonce      []byte
	KeyVersion uint64
}

// KMSDecryptResponse represents a decrypt response.
type KMSDecryptResponse struct {
	KeyID      string
	KeyVersion uint64
	Plaintext  []byte
	Timestamp  int64
}

// =============================================================================
// Batch Cryptographic Operation Types
// =============================================================================

// KMSBatchEncryptItem represents a single item to encrypt in a batch operation.
type KMSBatchEncryptItem struct {
	ItemID    string
	Plaintext []byte
	Context   []byte
	Nonce     []byte
}

// KMSBatchEncryptResultItem represents the result of encrypting a single item.
type KMSBatchEncryptResultItem struct {
	ItemID     string
	Success    bool
	Message    string
	Ciphertext []byte
	Nonce      []byte
	KeyVersion uint64
}

// KMSBatchEncryptRequest represents a batch encrypt request.
type KMSBatchEncryptRequest struct {
	KeyID string
	Items []*KMSBatchEncryptItem
}

// KMSBatchEncryptResponse represents a batch encrypt response.
type KMSBatchEncryptResponse struct {
	KeyID        string
	Results      []*KMSBatchEncryptResultItem
	SuccessCount int32
	FailureCount int32
	Timestamp    int64
}

// KMSBatchDecryptItem represents a single item to decrypt in a batch operation.
type KMSBatchDecryptItem struct {
	ItemID     string
	Ciphertext []byte
	Context    []byte
	Nonce      []byte
	KeyVersion uint64
}

// KMSBatchDecryptResultItem represents the result of decrypting a single item.
type KMSBatchDecryptResultItem struct {
	ItemID     string
	Success    bool
	Message    string
	Plaintext  []byte
	KeyVersion uint64
}

// KMSBatchDecryptRequest represents a batch decrypt request.
type KMSBatchDecryptRequest struct {
	KeyID string
	Items []*KMSBatchDecryptItem
}

// KMSBatchDecryptResponse represents a batch decrypt response.
type KMSBatchDecryptResponse struct {
	KeyID        string
	Results      []*KMSBatchDecryptResultItem
	SuccessCount int32
	FailureCount int32
	Timestamp    int64
}

// =============================================================================
// Rewrap Operation Types
// =============================================================================

// KMSRewrapRequest represents a rewrap request to re-encrypt ciphertext with the latest key version.
type KMSRewrapRequest struct {
	KeyID         string
	Ciphertext    []byte
	Context       []byte
	Nonce         []byte
	SourceVersion uint64
}

// KMSRewrapResponse represents a rewrap response.
type KMSRewrapResponse struct {
	KeyID         string
	SourceVersion uint64
	TargetVersion uint64
	Ciphertext    []byte
	Nonce         []byte
	Timestamp     int64
}

// =============================================================================
// Sign/Verify Operation Types
// =============================================================================

// KMSSignRequest represents a sign request.
type KMSSignRequest struct {
	KeyID         string
	Message       []byte
	HashAlgorithm int32
	PreHashed     bool
}

// KMSSignResponse represents a sign response.
type KMSSignResponse struct {
	KeyID         string
	KeyVersion    uint64
	Signature     []byte
	HashAlgorithm int32
	Timestamp     int64
}

// KMSVerifyRequest represents a verify request.
type KMSVerifyRequest struct {
	KeyID         string
	Message       []byte
	Signature     []byte
	HashAlgorithm int32
	KeyVersion    uint64
}

// KMSVerifyResponse represents a verify response.
type KMSVerifyResponse struct {
	KeyID      string
	KeyVersion uint64
	Valid      bool
	Timestamp  int64
}

// KMSHashRequest represents a hash request.
type KMSHashRequest struct {
	Data      []byte
	Algorithm int32
}

// KMSHashResponse represents a hash response.
type KMSHashResponse struct {
	Algorithm int32
	Hash      []byte
	Timestamp int64
}

// KMSHMACRequest represents an HMAC request.
type KMSHMACRequest struct {
	KeyID         string
	Message       []byte
	HashAlgorithm int32
}

// KMSHMACResponse represents an HMAC response.
type KMSHMACResponse struct {
	KeyID         string
	KeyVersion    uint64
	HMAC          []byte
	HashAlgorithm int32
	Timestamp     int64
}

// KMSVerifyHMACRequest represents a verify HMAC request.
type KMSVerifyHMACRequest struct {
	KeyID         string
	Message       []byte
	HMAC          []byte
	HashAlgorithm int32
	KeyVersion    uint64
}

// KMSVerifyHMACResponse represents a verify HMAC response.
type KMSVerifyHMACResponse struct {
	KeyID      string
	KeyVersion uint64
	Valid      bool
	Timestamp  int64
}

// KMSGenerateRandomRequest represents a generate random request.
type KMSGenerateRandomRequest struct {
	NumBytes int32
}

// KMSGenerateRandomResponse represents a generate random response.
type KMSGenerateRandomResponse struct {
	RandomBytes []byte
	Timestamp   int64
}

// =============================================================================
// Backend Status Types
// =============================================================================

// KMSBackendStatusResponse represents backend status response.
type KMSBackendStatusResponse struct {
	BackendType  string
	Status       string
	Device       string
	Region       string
	KeyID        string
	PcrBanks     []string
	PcrRegisters []int32
	Capabilities map[string]bool
	Timestamp    int64
}

// =============================================================================
// KMS Error Types
// =============================================================================

// ErrKMSOperationFailed is returned when a KMS operation fails.
type ErrKMSOperationFailed struct {
	Operation string
	Reason    string
}

func (e ErrKMSOperationFailed) Error() string {
	return "KMS operation " + e.Operation + " failed: " + e.Reason
}
