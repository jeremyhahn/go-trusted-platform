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

package quic

import (
	"context"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// KMS operation constants for pagination and limits
const (
	kmsDefaultLimit   int32 = 50
	kmsMaxLimit       int32 = 1000
	kmsMaxRandomBytes int32 = 1048576 // 1MB
	kmsMaxBatchItems  int32 = 100     // Maximum items in a batch operation
)

// KMS-specific sentinel errors
var (
	// ErrKMSServiceNotAvailable is returned when the KMS service is not configured
	// or unavailable.
	ErrKMSServiceNotAvailable = errors.New("KMS service not available")

	// ErrKMSMissingKeyID is returned when a key ID is required but not provided.
	ErrKMSMissingKeyID = errors.New("key ID is required")

	// ErrKMSMissingKeySpec is returned when a key specification is required but not provided.
	ErrKMSMissingKeySpec = errors.New("key specification is required")

	// ErrKMSMissingPlaintext is returned when plaintext is required but not provided.
	ErrKMSMissingPlaintext = errors.New("plaintext is required")

	// ErrKMSMissingCiphertext is returned when ciphertext is required but not provided.
	ErrKMSMissingCiphertext = errors.New("ciphertext is required")

	// ErrKMSMissingMessage is returned when a message is required but not provided.
	ErrKMSMissingMessage = errors.New("message is required")

	// ErrKMSMissingSignature is returned when a signature is required but not provided.
	ErrKMSMissingSignature = errors.New("signature is required")

	// ErrKMSMissingData is returned when data is required but not provided.
	ErrKMSMissingData = errors.New("data is required")

	// ErrKMSMissingHMAC is returned when HMAC is required but not provided.
	ErrKMSMissingHMAC = errors.New("HMAC is required")

	// ErrKMSInvalidNumBytes is returned when num_bytes is invalid.
	ErrKMSInvalidNumBytes = errors.New("invalid num_bytes value")

	// ErrKMSMissingKeyMaterial is returned when key material is required but not provided.
	ErrKMSMissingKeyMaterial = errors.New("key material is required")

	// ErrKMSMissingSourceKeyID is returned when the source key ID is required but not provided.
	ErrKMSMissingSourceKeyID = errors.New("source key ID is required")

	// ErrKMSMissingDestinationKeyID is returned when the destination key ID is required but not provided.
	ErrKMSMissingDestinationKeyID = errors.New("destination key ID is required")

	// ErrKMSEmptyBatch is returned when a batch operation has no items.
	ErrKMSEmptyBatch = errors.New("batch operation requires at least one item")

	// ErrKMSBatchTooLarge is returned when a batch operation exceeds the maximum size.
	ErrKMSBatchTooLarge = errors.New("batch operation exceeds maximum size")
)

// =============================================================================
// KMS Service Interface
// =============================================================================

// KMSService defines the interface for KMS operations.
type KMSService interface {
	// Key Management
	GenerateKey(ctx context.Context, req *KMSGenerateKeyRequest) (*KMSGenerateKeyResponse, error)
	ImportKey(ctx context.Context, req *KMSImportKeyRequest) (*KMSImportKeyResponse, error)
	GetKey(ctx context.Context, req *KMSGetKeyRequest) (*KMSGetKeyResponse, error)
	ListKeys(ctx context.Context, req *KMSListKeysRequest) (*KMSListKeysResponse, error)
	DeleteKey(ctx context.Context, req *KMSDeleteKeyRequest) (*KMSDeleteKeyResponse, error)
	RotateKey(ctx context.Context, req *KMSRotateKeyRequest) (*KMSRotateKeyResponse, error)
	UpdateKeyStatus(ctx context.Context, req *KMSUpdateKeyStatusRequest) (*KMSUpdateKeyStatusResponse, error)
	ExportKey(ctx context.Context, req *KMSExportKeyRequest) (*KMSExportKeyResponse, error)
	GetKeyVersions(ctx context.Context, req *KMSGetKeyVersionsRequest) (*KMSGetKeyVersionsResponse, error)
	BackendStatus(ctx context.Context) (*KMSBackendStatusResponse, error)

	// Crypto Operations
	Encrypt(ctx context.Context, req *KMSEncryptRequest) (*KMSEncryptResponse, error)
	Decrypt(ctx context.Context, req *KMSDecryptRequest) (*KMSDecryptResponse, error)
	BatchEncrypt(ctx context.Context, req *KMSBatchEncryptRequest) (*KMSBatchEncryptResponse, error)
	BatchDecrypt(ctx context.Context, req *KMSBatchDecryptRequest) (*KMSBatchDecryptResponse, error)
	Rewrap(ctx context.Context, req *KMSRewrapRequest) (*KMSRewrapResponse, error)
	Sign(ctx context.Context, req *KMSSignRequest) (*KMSSignResponse, error)
	Verify(ctx context.Context, req *KMSVerifyRequest) (*KMSVerifyResponse, error)
	GenerateRandom(ctx context.Context, req *KMSGenerateRandomRequest) (*KMSGenerateRandomResponse, error)
	Hash(ctx context.Context, req *KMSHashRequest) (*KMSHashResponse, error)
	HMAC(ctx context.Context, req *KMSHMACRequest) (*KMSHMACResponse, error)
	VerifyHMAC(ctx context.Context, req *KMSVerifyHMACRequest) (*KMSVerifyHMACResponse, error)
}

// =============================================================================
// KMS Request/Response Types
// =============================================================================

// KMSKeySpec defines the specification for a cryptographic key.
type KMSKeySpec struct {
	Algorithm          int32   `codec:"algorithm"`
	KeySize            int32   `codec:"key_size,omitempty"`
	Usage              []int32 `codec:"usage,omitempty"`
	Exportable         bool    `codec:"exportable,omitempty"`
	DeletionProtection bool    `codec:"deletion_protection,omitempty"`
}

// KMSKeyHandle represents a reference to a key.
type KMSKeyHandle struct {
	KeyID     string `codec:"key_id"`
	Version   uint64 `codec:"version"`
	Algorithm int32  `codec:"algorithm"`
	Status    int32  `codec:"status"`
	CreatedAt int64  `codec:"created_at"`
}

// KMSKeyMetadata contains metadata about a key.
type KMSKeyMetadata struct {
	KeyID              string            `codec:"key_id"`
	Name               string            `codec:"name,omitempty"`
	Description        string            `codec:"description,omitempty"`
	Algorithm          int32             `codec:"algorithm"`
	Status             int32             `codec:"status"`
	Usage              []int32           `codec:"usage,omitempty"`
	Version            uint64            `codec:"version"`
	Exportable         bool              `codec:"exportable,omitempty"`
	DeletionProtection bool              `codec:"deletion_protection,omitempty"`
	CreatedAt          int64             `codec:"created_at"`
	UpdatedAt          int64             `codec:"updated_at,omitempty"`
	LastUsedAt         int64             `codec:"last_used_at,omitempty"`
	Tags               map[string]string `codec:"tags,omitempty"`
	Owner              string            `codec:"owner,omitempty"`
}

// KMSKeyVersionInfo contains version-specific key information.
type KMSKeyVersionInfo struct {
	Version    uint64 `codec:"version"`
	Status     int32  `codec:"status"`
	Algorithm  int32  `codec:"algorithm"`
	CreatedAt  int64  `codec:"created_at"`
	DisabledAt int64  `codec:"disabled_at,omitempty"`
}

// KMSGenerateKeyRequest is the request for generating a new key.
type KMSGenerateKeyRequest struct {
	KeySpec     *KMSKeySpec       `codec:"key_spec"`
	Name        string            `codec:"name,omitempty"`
	Description string            `codec:"description,omitempty"`
	Tags        map[string]string `codec:"tags,omitempty"`
	Owner       string            `codec:"owner,omitempty"`
}

// KMSGenerateKeyResponse is the response from key generation.
type KMSGenerateKeyResponse struct {
	Key       *KMSKeyHandle   `codec:"key"`
	Metadata  *KMSKeyMetadata `codec:"metadata,omitempty"`
	Timestamp int64           `codec:"timestamp"`
}

// KMSImportKeyRequest is the request for importing a key.
type KMSImportKeyRequest struct {
	KeyMaterial   []byte            `codec:"key_material"`
	WrappingKeyID string            `codec:"wrapping_key_id,omitempty"`
	KeySpec       *KMSKeySpec       `codec:"key_spec"`
	Name          string            `codec:"name,omitempty"`
	Description   string            `codec:"description,omitempty"`
	Tags          map[string]string `codec:"tags,omitempty"`
}

// KMSImportKeyResponse is the response from key import.
type KMSImportKeyResponse struct {
	Key       *KMSKeyHandle   `codec:"key"`
	Metadata  *KMSKeyMetadata `codec:"metadata,omitempty"`
	Timestamp int64           `codec:"timestamp"`
}

// KMSGetKeyRequest is the request for retrieving a key.
type KMSGetKeyRequest struct {
	KeyID   string `codec:"key_id"`
	Version uint64 `codec:"version,omitempty"`
}

// KMSGetKeyResponse is the response from key retrieval.
type KMSGetKeyResponse struct {
	Key       *KMSKeyHandle   `codec:"key"`
	Metadata  *KMSKeyMetadata `codec:"metadata,omitempty"`
	Timestamp int64           `codec:"timestamp"`
}

// KMSListKeysRequest is the request for listing keys.
type KMSListKeysRequest struct {
	Limit  int32             `codec:"limit,omitempty"`
	Cursor string            `codec:"cursor,omitempty"`
	Filter map[string]string `codec:"filter,omitempty"`
}

// KMSListKeysResponse is the response from key listing.
type KMSListKeysResponse struct {
	Keys       []*KMSKeyHandle `codec:"keys"`
	NextCursor string          `codec:"next_cursor,omitempty"`
	HasMore    bool            `codec:"has_more"`
	TotalCount int32           `codec:"total_count"`
	Timestamp  int64           `codec:"timestamp"`
}

// KMSDeleteKeyRequest is the request for deleting a key.
type KMSDeleteKeyRequest struct {
	KeyID             string `codec:"key_id"`
	PendingWindowDays int32  `codec:"pending_window_days,omitempty"`
	Force             bool   `codec:"force,omitempty"`
}

// KMSDeleteKeyResponse is the response from key deletion.
type KMSDeleteKeyResponse struct {
	KeyID        string `codec:"key_id"`
	Status       int32  `codec:"status"`
	DeletionDate int64  `codec:"deletion_date,omitempty"`
	Timestamp    int64  `codec:"timestamp"`
}

// KMSRotateKeyRequest is the request for rotating a key.
type KMSRotateKeyRequest struct {
	KeyID            string `codec:"key_id"`
	RetainOldVersion bool   `codec:"retain_old_version,omitempty"`
}

// KMSRotateKeyResponse is the response from key rotation.
type KMSRotateKeyResponse struct {
	KeyID      string `codec:"key_id"`
	OldVersion uint64 `codec:"old_version"`
	NewVersion uint64 `codec:"new_version"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSUpdateKeyStatusRequest is the request for updating key status.
type KMSUpdateKeyStatusRequest struct {
	KeyID   string `codec:"key_id"`
	Version uint64 `codec:"version,omitempty"`
	Status  int32  `codec:"status"`
}

// KMSUpdateKeyStatusResponse is the response from status update.
type KMSUpdateKeyStatusResponse struct {
	KeyID     string `codec:"key_id"`
	Version   uint64 `codec:"version"`
	Status    int32  `codec:"status"`
	Timestamp int64  `codec:"timestamp"`
}

// KMSExportKeyRequest is the request for exporting a key.
type KMSExportKeyRequest struct {
	KeyID             string `codec:"key_id"`
	WrappingKeyID     string `codec:"wrapping_key_id,omitempty"`
	WrappingAlgorithm int32  `codec:"wrapping_algorithm,omitempty"`
	Format            int32  `codec:"format,omitempty"`
	Version           uint64 `codec:"version,omitempty"`
}

// KMSExportKeyResponse is the response from key export.
type KMSExportKeyResponse struct {
	KeyID             string `codec:"key_id"`
	Format            int32  `codec:"format"`
	WrappingKeyID     string `codec:"wrapping_key_id,omitempty"`
	WrappingAlgorithm int32  `codec:"wrapping_algorithm,omitempty"`
	WrappedMaterial   []byte `codec:"wrapped_material"`
	Version           uint64 `codec:"version"`
	Timestamp         int64  `codec:"timestamp"`
}

// KMSGetKeyVersionsRequest is the request for listing key versions.
type KMSGetKeyVersionsRequest struct {
	KeyID  string `codec:"key_id"`
	Limit  int32  `codec:"limit,omitempty"`
	Cursor string `codec:"cursor,omitempty"`
}

// KMSGetKeyVersionsResponse is the response from key version listing.
type KMSGetKeyVersionsResponse struct {
	KeyID      string               `codec:"key_id"`
	Versions   []*KMSKeyVersionInfo `codec:"versions"`
	NextCursor string               `codec:"next_cursor,omitempty"`
	HasMore    bool                 `codec:"has_more"`
	Timestamp  int64                `codec:"timestamp"`
}

// KMSBackendStatusResponse is the response from backend status check.
type KMSBackendStatusResponse struct {
	BackendType  string          `codec:"backend_type"`
	Status       string          `codec:"status"`
	Device       string          `codec:"device,omitempty"`
	Region       string          `codec:"region,omitempty"`
	KeyID        string          `codec:"key_id,omitempty"`
	PcrBanks     []string        `codec:"pcr_banks,omitempty"`
	PcrRegisters []int32         `codec:"pcr_registers,omitempty"`
	Capabilities map[string]bool `codec:"capabilities,omitempty"`
	Timestamp    int64           `codec:"timestamp"`
}

// KMSEncryptRequest is the request for encryption.
type KMSEncryptRequest struct {
	KeyID     string `codec:"key_id"`
	Plaintext []byte `codec:"plaintext"`
	Context   []byte `codec:"context,omitempty"`
	Nonce     []byte `codec:"nonce,omitempty"`
}

// KMSEncryptResponse is the response from encryption.
type KMSEncryptResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Ciphertext []byte `codec:"ciphertext"`
	Nonce      []byte `codec:"nonce,omitempty"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSDecryptRequest is the request for decryption.
type KMSDecryptRequest struct {
	KeyID      string `codec:"key_id"`
	Ciphertext []byte `codec:"ciphertext"`
	Context    []byte `codec:"context,omitempty"`
	Nonce      []byte `codec:"nonce,omitempty"`
	KeyVersion uint64 `codec:"key_version,omitempty"`
}

// KMSDecryptResponse is the response from decryption.
type KMSDecryptResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Plaintext  []byte `codec:"plaintext"`
	Timestamp  int64  `codec:"timestamp"`
}

// =============================================================================
// Batch Encrypt/Decrypt Types
// =============================================================================

// KMSBatchEncryptItem represents a single item in a batch encrypt request.
type KMSBatchEncryptItem struct {
	ID        string `codec:"id"`
	Plaintext []byte `codec:"plaintext"`
	Context   []byte `codec:"context,omitempty"`
}

// KMSBatchEncryptRequest is the request for batch encryption.
type KMSBatchEncryptRequest struct {
	KeyID string                 `codec:"key_id"`
	Items []*KMSBatchEncryptItem `codec:"items"`
}

// KMSBatchEncryptResultItem represents a single result in a batch encrypt response.
type KMSBatchEncryptResultItem struct {
	ID         string `codec:"id"`
	Ciphertext []byte `codec:"ciphertext,omitempty"`
	Nonce      []byte `codec:"nonce,omitempty"`
	Error      string `codec:"error,omitempty"`
	Success    bool   `codec:"success"`
}

// KMSBatchEncryptResponse is the response from batch encryption.
type KMSBatchEncryptResponse struct {
	KeyID        string                       `codec:"key_id"`
	KeyVersion   uint64                       `codec:"key_version"`
	Results      []*KMSBatchEncryptResultItem `codec:"results"`
	SuccessCount int32                        `codec:"success_count"`
	FailureCount int32                        `codec:"failure_count"`
	Timestamp    int64                        `codec:"timestamp"`
}

// KMSBatchDecryptItem represents a single item in a batch decrypt request.
type KMSBatchDecryptItem struct {
	ID         string `codec:"id"`
	Ciphertext []byte `codec:"ciphertext"`
	Context    []byte `codec:"context,omitempty"`
	Nonce      []byte `codec:"nonce,omitempty"`
	KeyVersion uint64 `codec:"key_version,omitempty"`
}

// KMSBatchDecryptRequest is the request for batch decryption.
type KMSBatchDecryptRequest struct {
	KeyID string                 `codec:"key_id"`
	Items []*KMSBatchDecryptItem `codec:"items"`
}

// KMSBatchDecryptResultItem represents a single result in a batch decrypt response.
type KMSBatchDecryptResultItem struct {
	ID        string `codec:"id"`
	Plaintext []byte `codec:"plaintext,omitempty"`
	Error     string `codec:"error,omitempty"`
	Success   bool   `codec:"success"`
}

// KMSBatchDecryptResponse is the response from batch decryption.
type KMSBatchDecryptResponse struct {
	KeyID        string                       `codec:"key_id"`
	Results      []*KMSBatchDecryptResultItem `codec:"results"`
	SuccessCount int32                        `codec:"success_count"`
	FailureCount int32                        `codec:"failure_count"`
	Timestamp    int64                        `codec:"timestamp"`
}

// =============================================================================
// Rewrap Types
// =============================================================================

// KMSRewrapRequest is the request for rewrapping ciphertext with a new key.
type KMSRewrapRequest struct {
	SourceKeyID      string `codec:"source_key_id"`
	DestinationKeyID string `codec:"destination_key_id"`
	Ciphertext       []byte `codec:"ciphertext"`
	SourceContext    []byte `codec:"source_context,omitempty"`
	DestContext      []byte `codec:"dest_context,omitempty"`
	SourceKeyVersion uint64 `codec:"source_key_version,omitempty"`
}

// KMSRewrapResponse is the response from rewrapping.
type KMSRewrapResponse struct {
	SourceKeyID      string `codec:"source_key_id"`
	DestinationKeyID string `codec:"destination_key_id"`
	Ciphertext       []byte `codec:"ciphertext"`
	SourceKeyVersion uint64 `codec:"source_key_version"`
	DestKeyVersion   uint64 `codec:"dest_key_version"`
	Timestamp        int64  `codec:"timestamp"`
}

// KMSSignRequest is the request for signing.
type KMSSignRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	HashAlgorithm int32  `codec:"hash_algorithm,omitempty"`
	PreHashed     bool   `codec:"pre_hashed,omitempty"`
}

// KMSSignResponse is the response from signing.
type KMSSignResponse struct {
	KeyID         string `codec:"key_id"`
	KeyVersion    uint64 `codec:"key_version"`
	Signature     []byte `codec:"signature"`
	HashAlgorithm int32  `codec:"hash_algorithm"`
	Timestamp     int64  `codec:"timestamp"`
}

// KMSVerifyRequest is the request for signature verification.
type KMSVerifyRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	Signature     []byte `codec:"signature"`
	HashAlgorithm int32  `codec:"hash_algorithm,omitempty"`
	KeyVersion    uint64 `codec:"key_version,omitempty"`
}

// KMSVerifyResponse is the response from signature verification.
type KMSVerifyResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Valid      bool   `codec:"valid"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSGenerateRandomRequest is the request for random byte generation.
type KMSGenerateRandomRequest struct {
	NumBytes int32 `codec:"num_bytes"`
}

// KMSGenerateRandomResponse is the response from random generation.
type KMSGenerateRandomResponse struct {
	RandomBytes []byte `codec:"random_bytes"`
	Timestamp   int64  `codec:"timestamp"`
}

// KMSHashRequest is the request for hashing.
type KMSHashRequest struct {
	Data      []byte `codec:"data"`
	Algorithm int32  `codec:"algorithm"`
}

// KMSHashResponse is the response from hashing.
type KMSHashResponse struct {
	Algorithm int32  `codec:"algorithm"`
	Hash      []byte `codec:"hash"`
	Timestamp int64  `codec:"timestamp"`
}

// KMSHMACRequest is the request for HMAC generation.
type KMSHMACRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	HashAlgorithm int32  `codec:"hash_algorithm,omitempty"`
}

// KMSHMACResponse is the response from HMAC generation.
type KMSHMACResponse struct {
	KeyID         string `codec:"key_id"`
	KeyVersion    uint64 `codec:"key_version"`
	HMAC          []byte `codec:"hmac"`
	HashAlgorithm int32  `codec:"hash_algorithm"`
	Timestamp     int64  `codec:"timestamp"`
}

// KMSVerifyHMACRequest is the request for HMAC verification.
type KMSVerifyHMACRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	HMAC          []byte `codec:"hmac"`
	HashAlgorithm int32  `codec:"hash_algorithm,omitempty"`
	KeyVersion    uint64 `codec:"key_version,omitempty"`
}

// KMSVerifyHMACResponse is the response from HMAC verification.
type KMSVerifyHMACResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Valid      bool   `codec:"valid"`
	Timestamp  int64  `codec:"timestamp"`
}

// =============================================================================
// KMS Handler
// =============================================================================

// KMSHandler handles KMS operations over QUIC
type KMSHandler struct {
	service KMSService
	logger  *logging.Logger
}

// NewKMSHandler creates a new KMS handler
func NewKMSHandler(logger *logging.Logger, service KMSService) *KMSHandler {
	return &KMSHandler{
		service: service,
		logger:  logger,
	}
}

// HandleRequest processes a KMS request and returns a response
func (h *KMSHandler) HandleRequest(ctx context.Context, req *Request) *Response {
	if req == nil {
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte(ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	// Key Management Operations
	case OpKMSGenerateKey:
		return h.handleGenerateKey(ctx, req)
	case OpKMSImportKey:
		return h.handleImportKey(ctx, req)
	case OpKMSGetKey:
		return h.handleGetKey(ctx, req)
	case OpKMSListKeys:
		return h.handleListKeys(ctx, req)
	case OpKMSDeleteKey:
		return h.handleDeleteKey(ctx, req)
	case OpKMSRotateKey:
		return h.handleRotateKey(ctx, req)
	case OpKMSUpdateKeyStatus:
		return h.handleUpdateKeyStatus(ctx, req)
	case OpKMSExportKey:
		return h.handleExportKey(ctx, req)
	case OpKMSGetKeyVersions:
		return h.handleGetKeyVersions(ctx, req)
	case OpKMSBackendStatus:
		return h.handleBackendStatus(ctx, req)

	// Crypto Operations
	case OpKMSEncrypt:
		return h.handleEncrypt(ctx, req)
	case OpKMSDecrypt:
		return h.handleDecrypt(ctx, req)
	case OpKMSBatchEncrypt:
		return h.handleBatchEncrypt(ctx, req)
	case OpKMSBatchDecrypt:
		return h.handleBatchDecrypt(ctx, req)
	case OpKMSRewrap:
		return h.handleRewrap(ctx, req)
	case OpKMSSign:
		return h.handleSign(ctx, req)
	case OpKMSVerify:
		return h.handleVerify(ctx, req)
	case OpKMSGenerateRandom:
		return h.handleGenerateRandom(ctx, req)
	case OpKMSHash:
		return h.handleHash(ctx, req)
	case OpKMSHMAC:
		return h.handleHMAC(ctx, req)
	case OpKMSVerifyHMAC:
		return h.handleVerifyHMAC(ctx, req)

	default:
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte("unknown KMS operation"),
		}
	}
}

// =============================================================================
// Key Management Handlers
// =============================================================================

// handleGenerateKey generates a new cryptographic key
func (h *KMSHandler) handleGenerateKey(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var genReq KMSGenerateKeyRequest
	if err := DecodePayload(req.Payload, &genReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if genReq.KeySpec == nil {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeySpec)
	}

	resp, err := h.service.GenerateKey(ctx, &genReq)
	if err != nil {
		h.logger.Error(err, "failed to generate key")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleImportKey imports a key into the KMS
func (h *KMSHandler) handleImportKey(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var importReq KMSImportKeyRequest
	if err := DecodePayload(req.Payload, &importReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if len(importReq.KeyMaterial) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyMaterial)
	}

	resp, err := h.service.ImportKey(ctx, &importReq)
	if err != nil {
		h.logger.Error(err, "failed to import key")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGetKey retrieves a key by ID
func (h *KMSHandler) handleGetKey(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var getReq KMSGetKeyRequest
	if err := DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if getReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	resp, err := h.service.GetKey(ctx, &getReq)
	if err != nil {
		h.logger.Error(err, "failed to get key")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleListKeys lists keys with pagination
func (h *KMSHandler) handleListKeys(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var listReq KMSListKeysRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	// Apply pagination limits
	if listReq.Limit <= 0 {
		listReq.Limit = kmsDefaultLimit
	} else if listReq.Limit > kmsMaxLimit {
		listReq.Limit = kmsMaxLimit
	}

	resp, err := h.service.ListKeys(ctx, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list keys")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleDeleteKey deletes a key
func (h *KMSHandler) handleDeleteKey(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var deleteReq KMSDeleteKeyRequest
	if err := DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if deleteReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	resp, err := h.service.DeleteKey(ctx, &deleteReq)
	if err != nil {
		h.logger.Error(err, "failed to delete key")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleRotateKey rotates a key
func (h *KMSHandler) handleRotateKey(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var rotateReq KMSRotateKeyRequest
	if err := DecodePayload(req.Payload, &rotateReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if rotateReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	resp, err := h.service.RotateKey(ctx, &rotateReq)
	if err != nil {
		h.logger.Error(err, "failed to rotate key")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleUpdateKeyStatus updates the status of a key
func (h *KMSHandler) handleUpdateKeyStatus(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var updateReq KMSUpdateKeyStatusRequest
	if err := DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if updateReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	resp, err := h.service.UpdateKeyStatus(ctx, &updateReq)
	if err != nil {
		h.logger.Error(err, "failed to update key status")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleExportKey exports a key
func (h *KMSHandler) handleExportKey(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var exportReq KMSExportKeyRequest
	if err := DecodePayload(req.Payload, &exportReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if exportReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	resp, err := h.service.ExportKey(ctx, &exportReq)
	if err != nil {
		h.logger.Error(err, "failed to export key")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGetKeyVersions retrieves versions of a key
func (h *KMSHandler) handleGetKeyVersions(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var versionsReq KMSGetKeyVersionsRequest
	if err := DecodePayload(req.Payload, &versionsReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if versionsReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	// Apply pagination limits
	if versionsReq.Limit <= 0 {
		versionsReq.Limit = kmsDefaultLimit
	} else if versionsReq.Limit > kmsMaxLimit {
		versionsReq.Limit = kmsMaxLimit
	}

	resp, err := h.service.GetKeyVersions(ctx, &versionsReq)
	if err != nil {
		h.logger.Error(err, "failed to get key versions")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleBackendStatus retrieves the status of the KMS backend
func (h *KMSHandler) handleBackendStatus(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	resp, err := h.service.BackendStatus(ctx)
	if err != nil {
		h.logger.Error(err, "failed to get backend status")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Crypto Operation Handlers
// =============================================================================

// handleEncrypt encrypts data with a key
func (h *KMSHandler) handleEncrypt(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var encryptReq KMSEncryptRequest
	if err := DecodePayload(req.Payload, &encryptReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if encryptReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	if len(encryptReq.Plaintext) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingPlaintext)
	}

	resp, err := h.service.Encrypt(ctx, &encryptReq)
	if err != nil {
		h.logger.Error(err, "failed to encrypt")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleDecrypt decrypts data with a key
func (h *KMSHandler) handleDecrypt(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var decryptReq KMSDecryptRequest
	if err := DecodePayload(req.Payload, &decryptReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if decryptReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	if len(decryptReq.Ciphertext) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingCiphertext)
	}

	resp, err := h.service.Decrypt(ctx, &decryptReq)
	if err != nil {
		h.logger.Error(err, "failed to decrypt")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleBatchEncrypt encrypts multiple items with a single key
func (h *KMSHandler) handleBatchEncrypt(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var batchReq KMSBatchEncryptRequest
	if err := DecodePayload(req.Payload, &batchReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if batchReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	if len(batchReq.Items) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSEmptyBatch)
	}

	if int32(len(batchReq.Items)) > kmsMaxBatchItems {
		return h.errorResponse(StatusInvalidArgument, ErrKMSBatchSizeExceeded{
			Count:    int32(len(batchReq.Items)),
			MaxCount: kmsMaxBatchItems,
		})
	}

	resp, err := h.service.BatchEncrypt(ctx, &batchReq)
	if err != nil {
		h.logger.Error(err, "failed to batch encrypt")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleBatchDecrypt decrypts multiple items with a single key
func (h *KMSHandler) handleBatchDecrypt(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var batchReq KMSBatchDecryptRequest
	if err := DecodePayload(req.Payload, &batchReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if batchReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	if len(batchReq.Items) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSEmptyBatch)
	}

	if int32(len(batchReq.Items)) > kmsMaxBatchItems {
		return h.errorResponse(StatusInvalidArgument, ErrKMSBatchSizeExceeded{
			Count:    int32(len(batchReq.Items)),
			MaxCount: kmsMaxBatchItems,
		})
	}

	resp, err := h.service.BatchDecrypt(ctx, &batchReq)
	if err != nil {
		h.logger.Error(err, "failed to batch decrypt")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleRewrap re-encrypts ciphertext with a different key
func (h *KMSHandler) handleRewrap(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var rewrapReq KMSRewrapRequest
	if err := DecodePayload(req.Payload, &rewrapReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if rewrapReq.SourceKeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingSourceKeyID)
	}

	if rewrapReq.DestinationKeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingDestinationKeyID)
	}

	if len(rewrapReq.Ciphertext) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingCiphertext)
	}

	resp, err := h.service.Rewrap(ctx, &rewrapReq)
	if err != nil {
		h.logger.Error(err, "failed to rewrap")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleSign signs a message with a key
func (h *KMSHandler) handleSign(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var signReq KMSSignRequest
	if err := DecodePayload(req.Payload, &signReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if signReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	if len(signReq.Message) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingMessage)
	}

	resp, err := h.service.Sign(ctx, &signReq)
	if err != nil {
		h.logger.Error(err, "failed to sign")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleVerify verifies a signature
func (h *KMSHandler) handleVerify(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var verifyReq KMSVerifyRequest
	if err := DecodePayload(req.Payload, &verifyReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if verifyReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	if len(verifyReq.Message) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingMessage)
	}

	if len(verifyReq.Signature) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingSignature)
	}

	resp, err := h.service.Verify(ctx, &verifyReq)
	if err != nil {
		h.logger.Error(err, "failed to verify")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGenerateRandom generates random bytes
func (h *KMSHandler) handleGenerateRandom(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var randomReq KMSGenerateRandomRequest
	if err := DecodePayload(req.Payload, &randomReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if randomReq.NumBytes <= 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSInvalidNumBytesValue{
			NumBytes: randomReq.NumBytes,
			Reason:   "must be greater than 0",
		})
	}

	if randomReq.NumBytes > kmsMaxRandomBytes {
		return h.errorResponse(StatusInvalidArgument, ErrKMSInvalidNumBytesValue{
			NumBytes: randomReq.NumBytes,
			Reason:   "exceeds maximum allowed (1MB)",
		})
	}

	resp, err := h.service.GenerateRandom(ctx, &randomReq)
	if err != nil {
		h.logger.Error(err, "failed to generate random bytes")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleHash computes a hash of data
func (h *KMSHandler) handleHash(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var hashReq KMSHashRequest
	if err := DecodePayload(req.Payload, &hashReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if len(hashReq.Data) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingData)
	}

	resp, err := h.service.Hash(ctx, &hashReq)
	if err != nil {
		h.logger.Error(err, "failed to hash")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleHMAC computes an HMAC
func (h *KMSHandler) handleHMAC(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var hmacReq KMSHMACRequest
	if err := DecodePayload(req.Payload, &hmacReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if hmacReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	if len(hmacReq.Message) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingMessage)
	}

	resp, err := h.service.HMAC(ctx, &hmacReq)
	if err != nil {
		h.logger.Error(err, "failed to compute HMAC")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleVerifyHMAC verifies an HMAC
func (h *KMSHandler) handleVerifyHMAC(ctx context.Context, req *Request) *Response {
	if h.service == nil {
		return h.errorResponse(StatusUnavailable, ErrKMSServiceNotAvailable)
	}

	var verifyReq KMSVerifyHMACRequest
	if err := DecodePayload(req.Payload, &verifyReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrKMSDecodingFailed{Cause: err})
	}

	if verifyReq.KeyID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingKeyID)
	}

	if len(verifyReq.Message) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingMessage)
	}

	if len(verifyReq.HMAC) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrKMSMissingHMAC)
	}

	resp, err := h.service.VerifyHMAC(ctx, &verifyReq)
	if err != nil {
		h.logger.Error(err, "failed to verify HMAC")
		return h.kmsErrorResponse(err)
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrKMSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Methods
// =============================================================================

// errorResponse creates an error response with the given status and error
func (h *KMSHandler) errorResponse(status byte, err error) *Response {
	return &Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// kmsErrorResponse maps KMS errors to appropriate status codes
func (h *KMSHandler) kmsErrorResponse(err error) *Response {
	var status byte

	switch e := err.(type) {
	case ErrKMSOpFailed:
		if e.Reason == "not implemented" {
			status = StatusNotImplemented
		} else {
			status = StatusInternalError
		}
	case ErrKMSKeyNotFound:
		status = StatusNotFound
	case ErrKMSKeyAlreadyExists:
		status = StatusAlreadyExists
	case ErrKMSInvalidKeySpecErr:
		status = StatusInvalidArgument
	case ErrKMSKeyNotExportable:
		status = StatusPermissionDenied
	case ErrKMSKeyDisabled:
		status = StatusPermissionDenied
	case ErrKMSKeyPendingDeletion:
		status = StatusPermissionDenied
	case ErrKMSEncryptFailed:
		status = StatusInternalError
	case ErrKMSDecryptFailed:
		status = StatusInternalError
	case ErrKMSSignFailed:
		status = StatusInternalError
	case ErrKMSVerifyFailed:
		status = StatusInternalError
	case ErrKMSInvalidAlgorithm:
		status = StatusInvalidArgument
	case ErrKMSUnavailable:
		status = StatusUnavailable
	case ErrKMSRewrapFailed:
		status = StatusInternalError
	case ErrKMSBatchSizeExceeded:
		status = StatusInvalidArgument
	default:
		status = StatusInternalError
	}

	return h.errorResponse(status, err)
}

// =============================================================================
// KMS Error Types
// =============================================================================

// ErrKMSEncodingFailed represents an encoding failure error
type ErrKMSEncodingFailed struct {
	Cause error
}

func (e ErrKMSEncodingFailed) Error() string {
	return "failed to encode KMS payload: " + e.Cause.Error()
}

func (e ErrKMSEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSDecodingFailed represents a decoding failure error
type ErrKMSDecodingFailed struct {
	Cause error
}

func (e ErrKMSDecodingFailed) Error() string {
	return "failed to decode KMS payload: " + e.Cause.Error()
}

func (e ErrKMSDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSOperationFailed represents a KMS operation failure
type ErrKMSOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrKMSOperationFailed) Error() string {
	return "KMS operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrKMSOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSInvalidNumBytesValue represents an invalid num_bytes value error
type ErrKMSInvalidNumBytesValue struct {
	NumBytes int32
	Reason   string
}

func (e ErrKMSInvalidNumBytesValue) Error() string {
	return fmt.Sprintf("invalid num_bytes %d: %s", e.NumBytes, e.Reason)
}

// ErrKMSOpFailed is returned when a KMS operation fails
type ErrKMSOpFailed struct {
	Operation string
	Reason    string
}

func (e ErrKMSOpFailed) Error() string {
	return fmt.Sprintf("KMS operation %s failed: %s", e.Operation, e.Reason)
}

// ErrKMSKeyNotFound is returned when a key is not found
type ErrKMSKeyNotFound struct {
	KeyID string
}

func (e ErrKMSKeyNotFound) Error() string {
	return fmt.Sprintf("key not found: %s", e.KeyID)
}

// ErrKMSKeyAlreadyExists is returned when a key already exists
type ErrKMSKeyAlreadyExists struct {
	KeyID string
}

func (e ErrKMSKeyAlreadyExists) Error() string {
	return fmt.Sprintf("key already exists: %s", e.KeyID)
}

// ErrKMSInvalidKeySpecErr is returned when a key specification is invalid
type ErrKMSInvalidKeySpecErr struct {
	Reason string
}

func (e ErrKMSInvalidKeySpecErr) Error() string {
	return fmt.Sprintf("invalid key specification: %s", e.Reason)
}

// ErrKMSKeyNotExportable is returned when attempting to export a non-exportable key
type ErrKMSKeyNotExportable struct {
	KeyID string
}

func (e ErrKMSKeyNotExportable) Error() string {
	return fmt.Sprintf("key is not exportable: %s", e.KeyID)
}

// ErrKMSKeyDisabled is returned when attempting to use a disabled key
type ErrKMSKeyDisabled struct {
	KeyID string
}

func (e ErrKMSKeyDisabled) Error() string {
	return fmt.Sprintf("key is disabled: %s", e.KeyID)
}

// ErrKMSKeyPendingDeletion is returned when attempting to use a key pending deletion
type ErrKMSKeyPendingDeletion struct {
	KeyID string
}

func (e ErrKMSKeyPendingDeletion) Error() string {
	return fmt.Sprintf("key is pending deletion: %s", e.KeyID)
}

// ErrKMSEncryptFailed is returned when encryption fails
type ErrKMSEncryptFailed struct {
	Err error
}

func (e ErrKMSEncryptFailed) Error() string {
	return fmt.Sprintf("encryption failed: %v", e.Err)
}

// ErrKMSDecryptFailed is returned when decryption fails
type ErrKMSDecryptFailed struct {
	Err error
}

func (e ErrKMSDecryptFailed) Error() string {
	return fmt.Sprintf("decryption failed: %v", e.Err)
}

// ErrKMSSignFailed is returned when signing fails
type ErrKMSSignFailed struct {
	Err error
}

func (e ErrKMSSignFailed) Error() string {
	return fmt.Sprintf("signing failed: %v", e.Err)
}

// ErrKMSVerifyFailed is returned when signature verification fails
type ErrKMSVerifyFailed struct {
	Err error
}

func (e ErrKMSVerifyFailed) Error() string {
	return fmt.Sprintf("signature verification failed: %v", e.Err)
}

// ErrKMSInvalidAlgorithm is returned when an invalid algorithm is specified
type ErrKMSInvalidAlgorithm struct {
	Algorithm int32
}

func (e ErrKMSInvalidAlgorithm) Error() string {
	return fmt.Sprintf("invalid algorithm: %d", e.Algorithm)
}

// ErrKMSUnavailable is returned when the KMS service is unavailable
type ErrKMSUnavailable struct {
	Reason string
}

func (e ErrKMSUnavailable) Error() string {
	return fmt.Sprintf("KMS service unavailable: %s", e.Reason)
}

// ErrKMSRewrapFailed is returned when rewrap operation fails
type ErrKMSRewrapFailed struct {
	Err error
}

func (e ErrKMSRewrapFailed) Error() string {
	return fmt.Sprintf("rewrap failed: %v", e.Err)
}

// ErrKMSBatchSizeExceeded is returned when a batch operation exceeds the maximum size
type ErrKMSBatchSizeExceeded struct {
	Count    int32
	MaxCount int32
}

func (e ErrKMSBatchSizeExceeded) Error() string {
	return fmt.Sprintf("batch size %d exceeds maximum allowed %d", e.Count, e.MaxCount)
}
