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

// Package rest provides REST API handlers for the trusted platform services.
package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
)

// =============================================================================
// KMS REST Handler Errors
// =============================================================================

// ErrKMSServiceNotAvailable is returned when the KMS service is not configured
// or unavailable.
type ErrKMSServiceNotAvailable struct{}

func (e ErrKMSServiceNotAvailable) Error() string {
	return "KMS service not available"
}

// ErrInvalidKeyID is returned when a key ID is invalid or empty.
type ErrInvalidKeyID struct {
	ID string
}

func (e ErrInvalidKeyID) Error() string {
	if e.ID == "" {
		return "key ID is required"
	}
	return fmt.Sprintf("invalid key ID: %s", e.ID)
}

// ErrKMSRequestBodyInvalid is returned when the KMS request body is invalid.
type ErrKMSRequestBodyInvalid struct {
	Reason string
}

func (e ErrKMSRequestBodyInvalid) Error() string {
	return fmt.Sprintf("invalid KMS request body: %s", e.Reason)
}

// ErrKMSMissingRequiredField is returned when a required field is missing.
type ErrKMSMissingRequiredField struct {
	Field string
}

func (e ErrKMSMissingRequiredField) Error() string {
	return fmt.Sprintf("missing required field: %s", e.Field)
}

// ErrKMSHandlerOperationFailed is returned when a KMS operation fails.
type ErrKMSHandlerOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrKMSHandlerOperationFailed) Error() string {
	return fmt.Sprintf("KMS operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrKMSHandlerOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidBase64 is returned when base64 decoding fails.
type ErrInvalidBase64 struct {
	Field string
	Cause error
}

func (e ErrInvalidBase64) Error() string {
	return fmt.Sprintf("invalid base64 encoding for field %s: %v", e.Field, e.Cause)
}

// ErrInvalidNumBytes is returned when num_bytes is invalid.
type ErrInvalidNumBytes struct {
	NumBytes int32
	Reason   string
}

func (e ErrInvalidNumBytes) Error() string {
	return fmt.Sprintf("invalid num_bytes %d: %s", e.NumBytes, e.Reason)
}

// =============================================================================
// Constants
// =============================================================================

const (
	kmsDefaultLimit   int32 = 50
	kmsMaxLimit       int32 = 1000
	kmsRequestTimeout       = 30 * time.Second
	kmsMaxRandomBytes int32 = 1048576 // 1MB
	kmsMaxBatchItems  int   = 100     // Maximum items in a batch operation
)

// =============================================================================
// Request/Response Types
// =============================================================================

// KMSKeySpecRequest is the request format for key specification.
type KMSKeySpecRequest struct {
	Algorithm          string   `json:"algorithm"`
	KeySize            int32    `json:"key_size,omitempty"`
	Usage              []string `json:"usage,omitempty"`
	Exportable         bool     `json:"exportable,omitempty"`
	DeletionProtection bool     `json:"deletion_protection,omitempty"`
}

// KMSGenerateKeyRequest is the request body for generating a key.
type KMSGenerateKeyRequest struct {
	KeySpec     KMSKeySpecRequest `json:"key_spec"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Owner       string            `json:"owner,omitempty"`
}

// KMSImportKeyRequest is the request body for importing a key.
type KMSImportKeyRequest struct {
	KeyMaterial   string            `json:"key_material"` // Base64 encoded
	WrappingKeyID string            `json:"wrapping_key_id,omitempty"`
	KeySpec       KMSKeySpecRequest `json:"key_spec"`
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
}

// KMSRotateKeyRequest is the request body for rotating a key.
type KMSRotateKeyRequest struct {
	RetainOldVersion bool `json:"retain_old_version,omitempty"`
}

// KMSExportKeyRequest is the request body for exporting a key.
type KMSExportKeyRequest struct {
	WrappingKeyID     string `json:"wrapping_key_id,omitempty"`
	WrappingAlgorithm int32  `json:"wrapping_algorithm,omitempty"`
	Format            int32  `json:"format,omitempty"`
	Version           uint64 `json:"version,omitempty"`
}

// KMSEncryptRequest is the request body for encryption.
type KMSEncryptRequest struct {
	KeyID     string `json:"key_id"`
	Plaintext string `json:"plaintext"` // Base64 encoded
	Context   string `json:"context,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
}

// KMSDecryptRequest is the request body for decryption.
type KMSDecryptRequest struct {
	KeyID      string `json:"key_id"`
	Ciphertext string `json:"ciphertext"` // Base64 encoded
	Context    string `json:"context,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty"`
}

// KMSBatchEncryptItemRequest represents a single item in a batch encryption request.
type KMSBatchEncryptItemRequest struct {
	Plaintext string `json:"plaintext"` // Base64 encoded
	Context   string `json:"context,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
}

// KMSBatchEncryptRequest is the request body for batch encryption.
type KMSBatchEncryptRequest struct {
	KeyID string                       `json:"key_id"`
	Items []KMSBatchEncryptItemRequest `json:"items"`
}

// KMSBatchDecryptItemRequest represents a single item in a batch decryption request.
type KMSBatchDecryptItemRequest struct {
	Ciphertext string `json:"ciphertext"` // Base64 encoded
	Context    string `json:"context,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty"`
}

// KMSBatchDecryptRequest is the request body for batch decryption.
type KMSBatchDecryptRequest struct {
	KeyID string                       `json:"key_id"`
	Items []KMSBatchDecryptItemRequest `json:"items"`
}

// KMSRewrapRequest is the request body for rewrapping ciphertext.
type KMSRewrapRequest struct {
	SourceKeyID      string `json:"source_key_id"`
	DestinationKeyID string `json:"destination_key_id"`
	Ciphertext       string `json:"ciphertext"` // Base64 encoded
	SourceContext    string `json:"source_context,omitempty"`
	DestContext      string `json:"dest_context,omitempty"`
	SourceNonce      string `json:"source_nonce,omitempty"`
	SourceKeyVersion uint64 `json:"source_key_version,omitempty"`
}

// KMSSignRequest is the request body for signing.
type KMSSignRequest struct {
	KeyID         string `json:"key_id"`
	Message       string `json:"message"` // Base64 encoded
	HashAlgorithm int32  `json:"hash_algorithm,omitempty"`
	PreHashed     bool   `json:"pre_hashed,omitempty"`
}

// KMSVerifyRequest is the request body for signature verification.
type KMSVerifyRequest struct {
	KeyID         string `json:"key_id"`
	Message       string `json:"message"`   // Base64 encoded
	Signature     string `json:"signature"` // Base64 encoded
	HashAlgorithm int32  `json:"hash_algorithm,omitempty"`
	KeyVersion    uint64 `json:"key_version,omitempty"`
}

// KMSHashRequest is the request body for hashing.
type KMSHashRequest struct {
	Data      string `json:"data"` // Base64 encoded
	Algorithm int32  `json:"algorithm,omitempty"`
}

// KMSHMACRequest is the request body for HMAC generation.
type KMSHMACRequest struct {
	KeyID         string `json:"key_id"`
	Message       string `json:"message"` // Base64 encoded
	HashAlgorithm int32  `json:"hash_algorithm,omitempty"`
}

// KMSRandomRequest is the request body for random bytes generation.
type KMSRandomRequest struct {
	NumBytes int32 `json:"num_bytes"`
}

// KMSKeyHandleResponse represents a key handle in API responses.
type KMSKeyHandleResponse struct {
	KeyID     string `json:"key_id"`
	Version   uint64 `json:"version"`
	Algorithm int32  `json:"algorithm"`
	Status    int32  `json:"status"`
	CreatedAt int64  `json:"created_at"`
}

// KMSKeyMetadataResponse represents key metadata in API responses.
type KMSKeyMetadataResponse struct {
	KeyID              string            `json:"key_id"`
	Name               string            `json:"name,omitempty"`
	Description        string            `json:"description,omitempty"`
	Algorithm          int32             `json:"algorithm"`
	Status             int32             `json:"status"`
	Usage              []int32           `json:"usage,omitempty"`
	Version            uint64            `json:"version"`
	Exportable         bool              `json:"exportable"`
	DeletionProtection bool              `json:"deletion_protection"`
	CreatedAt          int64             `json:"created_at"`
	UpdatedAt          int64             `json:"updated_at,omitempty"`
	LastUsedAt         int64             `json:"last_used_at,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
	Owner              string            `json:"owner,omitempty"`
}

// KMSGenerateKeyResponse is the response for key generation.
type KMSGenerateKeyResponse struct {
	Key       *KMSKeyHandleResponse   `json:"key"`
	Metadata  *KMSKeyMetadataResponse `json:"metadata,omitempty"`
	Timestamp int64                   `json:"timestamp"`
}

// KMSImportKeyResponse is the response for key import.
type KMSImportKeyResponse struct {
	Key       *KMSKeyHandleResponse   `json:"key"`
	Metadata  *KMSKeyMetadataResponse `json:"metadata,omitempty"`
	Timestamp int64                   `json:"timestamp"`
}

// KMSGetKeyResponse is the response for getting a key.
type KMSGetKeyResponse struct {
	Key       *KMSKeyHandleResponse   `json:"key"`
	Metadata  *KMSKeyMetadataResponse `json:"metadata,omitempty"`
	Timestamp int64                   `json:"timestamp"`
}

// KMSListKeysResponse is the response for listing keys.
type KMSListKeysResponse struct {
	Keys       []KMSKeyHandleResponse `json:"keys"`
	NextCursor string                 `json:"next_cursor,omitempty"`
	HasMore    bool                   `json:"has_more"`
	TotalCount int32                  `json:"total_count"`
	Timestamp  int64                  `json:"timestamp"`
}

// KMSDeleteKeyResponse is the response for key deletion.
type KMSDeleteKeyResponse struct {
	KeyID        string `json:"key_id"`
	Status       int32  `json:"status"`
	DeletionDate int64  `json:"deletion_date,omitempty"`
	Timestamp    int64  `json:"timestamp"`
}

// KMSRotateKeyResponse is the response for key rotation.
type KMSRotateKeyResponse struct {
	KeyID      string `json:"key_id"`
	OldVersion uint64 `json:"old_version"`
	NewVersion uint64 `json:"new_version"`
	Timestamp  int64  `json:"timestamp"`
}

// KMSExportKeyResponse is the response for key export.
type KMSExportKeyResponse struct {
	KeyID             string `json:"key_id"`
	Format            int32  `json:"format"`
	WrappingKeyID     string `json:"wrapping_key_id,omitempty"`
	WrappingAlgorithm int32  `json:"wrapping_algorithm,omitempty"`
	WrappedMaterial   string `json:"wrapped_material"` // Base64 encoded
	Version           uint64 `json:"version"`
	Timestamp         int64  `json:"timestamp"`
}

// KMSKeyVersionInfoResponse represents version info in responses.
type KMSKeyVersionInfoResponse struct {
	Version    uint64 `json:"version"`
	Status     int32  `json:"status"`
	Algorithm  int32  `json:"algorithm"`
	CreatedAt  int64  `json:"created_at"`
	DisabledAt int64  `json:"disabled_at,omitempty"`
}

// KMSGetKeyVersionsResponse is the response for listing key versions.
type KMSGetKeyVersionsResponse struct {
	KeyID      string                      `json:"key_id"`
	Versions   []KMSKeyVersionInfoResponse `json:"versions"`
	NextCursor string                      `json:"next_cursor,omitempty"`
	HasMore    bool                        `json:"has_more"`
	Timestamp  int64                       `json:"timestamp"`
}

// KMSEncryptResponse is the response for encryption.
type KMSEncryptResponse struct {
	KeyID      string `json:"key_id"`
	KeyVersion uint64 `json:"key_version"`
	Ciphertext string `json:"ciphertext"` // Base64 encoded
	Nonce      string `json:"nonce,omitempty"`
	Timestamp  int64  `json:"timestamp"`
}

// KMSDecryptResponse is the response for decryption.
type KMSDecryptResponse struct {
	KeyID      string `json:"key_id"`
	KeyVersion uint64 `json:"key_version"`
	Plaintext  string `json:"plaintext"` // Base64 encoded
	Timestamp  int64  `json:"timestamp"`
}

// KMSBatchEncryptResultItemResponse represents a single result in a batch encryption response.
type KMSBatchEncryptResultItemResponse struct {
	Ciphertext string `json:"ciphertext,omitempty"` // Base64 encoded
	Nonce      string `json:"nonce,omitempty"`
	Error      string `json:"error,omitempty"`
}

// KMSBatchEncryptResponse is the response for batch encryption.
type KMSBatchEncryptResponse struct {
	KeyID        string                              `json:"key_id"`
	KeyVersion   uint64                              `json:"key_version"`
	Results      []KMSBatchEncryptResultItemResponse `json:"results"`
	SuccessCount int32                               `json:"success_count"`
	FailureCount int32                               `json:"failure_count"`
	Timestamp    int64                               `json:"timestamp"`
}

// KMSBatchDecryptResultItemResponse represents a single result in a batch decryption response.
type KMSBatchDecryptResultItemResponse struct {
	Plaintext  string `json:"plaintext,omitempty"` // Base64 encoded
	KeyVersion uint64 `json:"key_version,omitempty"`
	Error      string `json:"error,omitempty"`
}

// KMSBatchDecryptResponse is the response for batch decryption.
type KMSBatchDecryptResponse struct {
	KeyID        string                              `json:"key_id"`
	Results      []KMSBatchDecryptResultItemResponse `json:"results"`
	SuccessCount int32                               `json:"success_count"`
	FailureCount int32                               `json:"failure_count"`
	Timestamp    int64                               `json:"timestamp"`
}

// KMSRewrapResponse is the response for rewrapping ciphertext.
type KMSRewrapResponse struct {
	SourceKeyID      string `json:"source_key_id"`
	DestinationKeyID string `json:"destination_key_id"`
	SourceKeyVersion uint64 `json:"source_key_version"`
	DestKeyVersion   uint64 `json:"dest_key_version"`
	Ciphertext       string `json:"ciphertext"` // Base64 encoded
	Nonce            string `json:"nonce,omitempty"`
	Timestamp        int64  `json:"timestamp"`
}

// KMSSignResponse is the response for signing.
type KMSSignResponse struct {
	KeyID         string `json:"key_id"`
	KeyVersion    uint64 `json:"key_version"`
	Signature     string `json:"signature"` // Base64 encoded
	HashAlgorithm int32  `json:"hash_algorithm"`
	Timestamp     int64  `json:"timestamp"`
}

// KMSVerifyResponse is the response for verification.
type KMSVerifyResponse struct {
	KeyID      string `json:"key_id"`
	KeyVersion uint64 `json:"key_version"`
	Valid      bool   `json:"valid"`
	Timestamp  int64  `json:"timestamp"`
}

// KMSHashResponse is the response for hashing.
type KMSHashResponse struct {
	Algorithm int32  `json:"algorithm"`
	Hash      string `json:"hash"` // Base64 encoded
	Timestamp int64  `json:"timestamp"`
}

// KMSHMACResponse is the response for HMAC generation.
type KMSHMACResponse struct {
	KeyID         string `json:"key_id"`
	KeyVersion    uint64 `json:"key_version"`
	HMAC          string `json:"hmac"` // Base64 encoded
	HashAlgorithm int32  `json:"hash_algorithm"`
	Timestamp     int64  `json:"timestamp"`
}

// KMSRandomResponse is the response for random bytes generation.
type KMSRandomResponse struct {
	RandomBytes string `json:"random_bytes"` // Base64 encoded
	Timestamp   int64  `json:"timestamp"`
}

// KMSBackendStatusResponse is the response for backend status.
type KMSBackendStatusResponse struct {
	BackendType  string          `json:"backend_type"`
	Status       string          `json:"status"`
	Device       string          `json:"device,omitempty"`
	Region       string          `json:"region,omitempty"`
	KeyID        string          `json:"key_id,omitempty"`
	PCRBanks     []string        `json:"pcr_banks,omitempty"`
	PCRRegisters []int32         `json:"pcr_registers,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	Timestamp    int64           `json:"timestamp"`
}

// =============================================================================
// KMS Handlers
// =============================================================================

// KMSHandlers provides REST API handlers for KMS operations.
type KMSHandlers struct {
	service KMSService
	logger  *slog.Logger
}

// NewKMSHandlers creates a new KMSHandlers instance.
func NewKMSHandlers(service KMSService, logger *slog.Logger) *KMSHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &KMSHandlers{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers all KMS routes on the provided router.
func (h *KMSHandlers) RegisterRoutes(router *mux.Router) {
	// Key management operations
	router.HandleFunc("/api/v1/kms/keys", h.handleGenerateKey).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/keys", h.handleListKeys).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/kms/keys/import", h.handleImportKey).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/keys/{id}", h.handleGetKey).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/kms/keys/{id}", h.handleDeleteKey).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/kms/keys/{id}/rotate", h.handleRotateKey).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/keys/{id}/export", h.handleExportKey).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/kms/keys/{id}/versions", h.handleGetKeyVersions).Methods(http.MethodGet)

	// Cryptographic operations
	router.HandleFunc("/api/v1/kms/encrypt", h.handleEncrypt).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/decrypt", h.handleDecrypt).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/batch-encrypt", h.handleBatchEncrypt).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/batch-decrypt", h.handleBatchDecrypt).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/rewrap", h.handleRewrap).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/sign", h.handleSign).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/verify", h.handleVerify).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/hash", h.handleHash).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/hmac", h.handleHMAC).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/kms/random", h.handleRandom).Methods(http.MethodPost)

	// Backend status
	router.HandleFunc("/api/v1/kms/status", h.handleBackendStatus).Methods(http.MethodGet)

	h.logger.Info("KMS REST routes registered")
}

// =============================================================================
// Key Management Handlers
// =============================================================================

// handleGenerateKey handles POST /api/v1/kms/keys
func (h *KMSHandlers) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSGenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "name"})
		return
	}

	if req.KeySpec.Algorithm == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "key_spec.algorithm"})
		return
	}

	// Convert request to service format
	serviceReq := &KMSGenerateKeyServiceRequest{
		KeySpec:     h.keySpecRequestToService(&req.KeySpec),
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
		Owner:       req.Owner,
	}

	resp, err := h.service.GenerateKey(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to generate key", "error", err, "name", req.Name)
		h.writeKMSError(w, "generate_key", err)
		return
	}

	apiResp := KMSGenerateKeyResponse{
		Key:       h.keyHandleToResponse(resp.Key),
		Metadata:  h.keyMetadataToResponse(resp.Metadata),
		Timestamp: resp.Timestamp,
	}

	h.logger.Info("Key generated", "key_id", resp.Key.KeyID, "name", req.Name)
	h.writeJSON(w, http.StatusCreated, apiResp)
}

// handleListKeys handles GET /api/v1/kms/keys
func (h *KMSHandlers) handleListKeys(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	limit, cursor := h.getPaginationParams(r)

	// Parse filter parameters
	filter := make(map[string]string)
	for key, values := range r.URL.Query() {
		if key != "limit" && key != "cursor" && len(values) > 0 {
			filter[key] = values[0]
		}
	}

	serviceReq := &KMSListKeysServiceRequest{
		Limit:  limit,
		Cursor: cursor,
		Filter: filter,
	}

	resp, err := h.service.ListKeys(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to list keys", "error", err)
		h.writeKMSError(w, "list_keys", err)
		return
	}

	keys := make([]KMSKeyHandleResponse, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, *h.keyHandleToResponse(k))
	}

	apiResp := KMSListKeysResponse{
		Keys:       keys,
		NextCursor: resp.NextCursor,
		HasMore:    resp.HasMore,
		TotalCount: resp.TotalCount,
		Timestamp:  resp.Timestamp,
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleGetKey handles GET /api/v1/kms/keys/{id}
func (h *KMSHandlers) handleGetKey(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]
	if keyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidKeyID{})
		return
	}

	// Parse optional version from query string
	var version uint64
	if v := r.URL.Query().Get("version"); v != "" {
		if parsed, err := strconv.ParseUint(v, 10, 64); err == nil {
			version = parsed
		}
	}

	serviceReq := &KMSGetKeyServiceRequest{
		KeyID:   keyID,
		Version: version,
	}

	resp, err := h.service.GetKey(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to get key", "error", err, "key_id", keyID)
		h.writeKMSError(w, "get_key", err)
		return
	}

	apiResp := KMSGetKeyResponse{
		Key:       h.keyHandleToResponse(resp.Key),
		Metadata:  h.keyMetadataToResponse(resp.Metadata),
		Timestamp: resp.Timestamp,
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleDeleteKey handles DELETE /api/v1/kms/keys/{id}
func (h *KMSHandlers) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]
	if keyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidKeyID{})
		return
	}

	// Parse optional parameters from query string
	var pendingWindowDays int32
	var force bool

	if pwd := r.URL.Query().Get("pending_window_days"); pwd != "" {
		if parsed, err := strconv.ParseInt(pwd, 10, 32); err == nil {
			pendingWindowDays = int32(parsed)
		}
	}

	if f := r.URL.Query().Get("force"); f == "true" {
		force = true
	}

	serviceReq := &KMSDeleteKeyServiceRequest{
		KeyID:             keyID,
		PendingWindowDays: pendingWindowDays,
		Force:             force,
	}

	resp, err := h.service.DeleteKey(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to delete key", "error", err, "key_id", keyID)
		h.writeKMSError(w, "delete_key", err)
		return
	}

	apiResp := KMSDeleteKeyResponse{
		KeyID:        resp.KeyID,
		Status:       resp.Status,
		DeletionDate: resp.DeletionDate,
		Timestamp:    resp.Timestamp,
	}

	h.logger.Info("Key deleted", "key_id", keyID)
	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleRotateKey handles POST /api/v1/kms/keys/{id}/rotate
func (h *KMSHandlers) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]
	if keyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidKeyID{})
		return
	}

	var req KMSRotateKeyRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
			return
		}
	}

	serviceReq := &KMSRotateKeyServiceRequest{
		KeyID:            keyID,
		RetainOldVersion: req.RetainOldVersion,
	}

	resp, err := h.service.RotateKey(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to rotate key", "error", err, "key_id", keyID)
		h.writeKMSError(w, "rotate_key", err)
		return
	}

	apiResp := KMSRotateKeyResponse{
		KeyID:      resp.KeyID,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		Timestamp:  resp.Timestamp,
	}

	h.logger.Info("Key rotated", "key_id", keyID, "new_version", resp.NewVersion)
	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleExportKey handles GET /api/v1/kms/keys/{id}/export
func (h *KMSHandlers) handleExportKey(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]
	if keyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidKeyID{})
		return
	}

	// Parse optional parameters from query string
	var wrappingKeyID string
	var wrappingAlgorithm int32
	var format int32
	var version uint64

	wrappingKeyID = r.URL.Query().Get("wrapping_key_id")

	if wa := r.URL.Query().Get("wrapping_algorithm"); wa != "" {
		if parsed, err := strconv.ParseInt(wa, 10, 32); err == nil {
			wrappingAlgorithm = int32(parsed)
		}
	}

	if f := r.URL.Query().Get("format"); f != "" {
		if parsed, err := strconv.ParseInt(f, 10, 32); err == nil {
			format = int32(parsed)
		}
	}

	if v := r.URL.Query().Get("version"); v != "" {
		if parsed, err := strconv.ParseUint(v, 10, 64); err == nil {
			version = parsed
		}
	}

	serviceReq := &KMSExportKeyServiceRequest{
		KeyID:             keyID,
		WrappingKeyID:     wrappingKeyID,
		WrappingAlgorithm: wrappingAlgorithm,
		Format:            format,
		Version:           version,
	}

	resp, err := h.service.ExportKey(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to export key", "error", err, "key_id", keyID)
		h.writeKMSError(w, "export_key", err)
		return
	}

	apiResp := KMSExportKeyResponse{
		KeyID:             resp.KeyID,
		Format:            resp.Format,
		WrappingKeyID:     resp.WrappingKeyID,
		WrappingAlgorithm: resp.WrappingAlgorithm,
		WrappedMaterial:   base64.StdEncoding.EncodeToString(resp.WrappedMaterial),
		Version:           resp.Version,
		Timestamp:         resp.Timestamp,
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleGetKeyVersions handles GET /api/v1/kms/keys/{id}/versions
func (h *KMSHandlers) handleGetKeyVersions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]
	if keyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidKeyID{})
		return
	}

	limit, cursor := h.getPaginationParams(r)

	serviceReq := &KMSGetKeyVersionsServiceRequest{
		KeyID:  keyID,
		Limit:  limit,
		Cursor: cursor,
	}

	resp, err := h.service.GetKeyVersions(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to get key versions", "error", err, "key_id", keyID)
		h.writeKMSError(w, "get_key_versions", err)
		return
	}

	versions := make([]KMSKeyVersionInfoResponse, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		versions = append(versions, KMSKeyVersionInfoResponse{
			Version:    v.Version,
			Status:     v.Status,
			Algorithm:  v.Algorithm,
			CreatedAt:  v.CreatedAt,
			DisabledAt: v.DisabledAt,
		})
	}

	apiResp := KMSGetKeyVersionsResponse{
		KeyID:      resp.KeyID,
		Versions:   versions,
		NextCursor: resp.NextCursor,
		HasMore:    resp.HasMore,
		Timestamp:  resp.Timestamp,
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleImportKey handles POST /api/v1/kms/keys/import
func (h *KMSHandlers) handleImportKey(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSImportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.KeyMaterial == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "key_material"})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "name"})
		return
	}

	// Decode base64 key material
	keyMaterial, err := base64.StdEncoding.DecodeString(req.KeyMaterial)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "key_material", Cause: err})
		return
	}

	serviceReq := &KMSImportKeyServiceRequest{
		KeyMaterial:   keyMaterial,
		WrappingKeyID: req.WrappingKeyID,
		KeySpec:       h.keySpecRequestToService(&req.KeySpec),
		Name:          req.Name,
		Description:   req.Description,
		Tags:          req.Tags,
	}

	resp, err := h.service.ImportKey(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to import key", "error", err, "name", req.Name)
		h.writeKMSError(w, "import_key", err)
		return
	}

	apiResp := KMSImportKeyResponse{
		Key:       h.keyHandleToResponse(resp.Key),
		Metadata:  h.keyMetadataToResponse(resp.Metadata),
		Timestamp: resp.Timestamp,
	}

	h.logger.Info("Key imported", "key_id", resp.Key.KeyID, "name", req.Name)
	h.writeJSON(w, http.StatusCreated, apiResp)
}

// =============================================================================
// Cryptographic Operation Handlers
// =============================================================================

// handleEncrypt handles POST /api/v1/kms/encrypt
func (h *KMSHandlers) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.KeyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "key_id"})
		return
	}

	if req.Plaintext == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "plaintext"})
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "plaintext", Cause: err})
		return
	}

	var encContext []byte
	if req.Context != "" {
		encContext, err = base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "context", Cause: err})
			return
		}
	}

	var nonce []byte
	if req.Nonce != "" {
		nonce, err = base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "nonce", Cause: err})
			return
		}
	}

	serviceReq := &KMSEncryptServiceRequest{
		KeyID:     req.KeyID,
		Plaintext: plaintext,
		Context:   encContext,
		Nonce:     nonce,
	}

	resp, err := h.service.Encrypt(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to encrypt", "error", err, "key_id", req.KeyID)
		h.writeKMSError(w, "encrypt", err)
		return
	}

	apiResp := KMSEncryptResponse{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Ciphertext: base64.StdEncoding.EncodeToString(resp.Ciphertext),
		Timestamp:  resp.Timestamp,
	}
	if len(resp.Nonce) > 0 {
		apiResp.Nonce = base64.StdEncoding.EncodeToString(resp.Nonce)
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleDecrypt handles POST /api/v1/kms/decrypt
func (h *KMSHandlers) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSDecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.KeyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "key_id"})
		return
	}

	if req.Ciphertext == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "ciphertext"})
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "ciphertext", Cause: err})
		return
	}

	var decContext []byte
	if req.Context != "" {
		decContext, err = base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "context", Cause: err})
			return
		}
	}

	var nonce []byte
	if req.Nonce != "" {
		nonce, err = base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "nonce", Cause: err})
			return
		}
	}

	serviceReq := &KMSDecryptServiceRequest{
		KeyID:      req.KeyID,
		Ciphertext: ciphertext,
		Context:    decContext,
		Nonce:      nonce,
		KeyVersion: req.KeyVersion,
	}

	resp, err := h.service.Decrypt(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to decrypt", "error", err, "key_id", req.KeyID)
		h.writeKMSError(w, "decrypt", err)
		return
	}

	apiResp := KMSDecryptResponse{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Plaintext:  base64.StdEncoding.EncodeToString(resp.Plaintext),
		Timestamp:  resp.Timestamp,
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleBatchEncrypt handles POST /api/v1/kms/batch-encrypt
func (h *KMSHandlers) handleBatchEncrypt(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSBatchEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.KeyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "key_id"})
		return
	}

	if len(req.Items) == 0 {
		h.writeError(w, http.StatusBadRequest, ErrKMSBatchItemsEmpty{})
		return
	}

	if len(req.Items) > kmsMaxBatchItems {
		h.writeError(w, http.StatusBadRequest, ErrKMSBatchItemsTooMany{Count: len(req.Items), Max: kmsMaxBatchItems})
		return
	}

	// Convert items to service format
	serviceItems := make([]*KMSBatchEncryptItem, 0, len(req.Items))
	for i, item := range req.Items {
		if item.Plaintext == "" {
			h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: fmt.Sprintf("items[%d].plaintext", i)})
			return
		}

		plaintext, err := base64.StdEncoding.DecodeString(item.Plaintext)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: fmt.Sprintf("items[%d].plaintext", i), Cause: err})
			return
		}

		var encContext []byte
		if item.Context != "" {
			encContext, err = base64.StdEncoding.DecodeString(item.Context)
			if err != nil {
				h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: fmt.Sprintf("items[%d].context", i), Cause: err})
				return
			}
		}

		var nonce []byte
		if item.Nonce != "" {
			nonce, err = base64.StdEncoding.DecodeString(item.Nonce)
			if err != nil {
				h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: fmt.Sprintf("items[%d].nonce", i), Cause: err})
				return
			}
		}

		serviceItems = append(serviceItems, &KMSBatchEncryptItem{
			Plaintext: plaintext,
			Context:   encContext,
			Nonce:     nonce,
		})
	}

	serviceReq := &KMSBatchEncryptServiceRequest{
		KeyID: req.KeyID,
		Items: serviceItems,
	}

	resp, err := h.service.BatchEncrypt(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to batch encrypt", "error", err, "key_id", req.KeyID, "item_count", len(req.Items))
		h.writeKMSError(w, "batch_encrypt", err)
		return
	}

	// Convert results to API response format
	results := make([]KMSBatchEncryptResultItemResponse, 0, len(resp.Results))
	for _, result := range resp.Results {
		item := KMSBatchEncryptResultItemResponse{
			Error: result.Error,
		}
		if len(result.Ciphertext) > 0 {
			item.Ciphertext = base64.StdEncoding.EncodeToString(result.Ciphertext)
		}
		if len(result.Nonce) > 0 {
			item.Nonce = base64.StdEncoding.EncodeToString(result.Nonce)
		}
		results = append(results, item)
	}

	apiResp := KMSBatchEncryptResponse{
		KeyID:        resp.KeyID,
		KeyVersion:   resp.KeyVersion,
		Results:      results,
		SuccessCount: resp.SuccessCount,
		FailureCount: resp.FailureCount,
		Timestamp:    resp.Timestamp,
	}

	h.logger.Info("Batch encrypt completed", "key_id", req.KeyID, "success_count", resp.SuccessCount, "failure_count", resp.FailureCount)
	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleBatchDecrypt handles POST /api/v1/kms/batch-decrypt
func (h *KMSHandlers) handleBatchDecrypt(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSBatchDecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.KeyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "key_id"})
		return
	}

	if len(req.Items) == 0 {
		h.writeError(w, http.StatusBadRequest, ErrKMSBatchItemsEmpty{})
		return
	}

	if len(req.Items) > kmsMaxBatchItems {
		h.writeError(w, http.StatusBadRequest, ErrKMSBatchItemsTooMany{Count: len(req.Items), Max: kmsMaxBatchItems})
		return
	}

	// Convert items to service format
	serviceItems := make([]*KMSBatchDecryptItem, 0, len(req.Items))
	for i, item := range req.Items {
		if item.Ciphertext == "" {
			h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: fmt.Sprintf("items[%d].ciphertext", i)})
			return
		}

		ciphertext, err := base64.StdEncoding.DecodeString(item.Ciphertext)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: fmt.Sprintf("items[%d].ciphertext", i), Cause: err})
			return
		}

		var decContext []byte
		if item.Context != "" {
			decContext, err = base64.StdEncoding.DecodeString(item.Context)
			if err != nil {
				h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: fmt.Sprintf("items[%d].context", i), Cause: err})
				return
			}
		}

		var nonce []byte
		if item.Nonce != "" {
			nonce, err = base64.StdEncoding.DecodeString(item.Nonce)
			if err != nil {
				h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: fmt.Sprintf("items[%d].nonce", i), Cause: err})
				return
			}
		}

		serviceItems = append(serviceItems, &KMSBatchDecryptItem{
			Ciphertext: ciphertext,
			Context:    decContext,
			Nonce:      nonce,
			KeyVersion: item.KeyVersion,
		})
	}

	serviceReq := &KMSBatchDecryptServiceRequest{
		KeyID: req.KeyID,
		Items: serviceItems,
	}

	resp, err := h.service.BatchDecrypt(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to batch decrypt", "error", err, "key_id", req.KeyID, "item_count", len(req.Items))
		h.writeKMSError(w, "batch_decrypt", err)
		return
	}

	// Convert results to API response format
	results := make([]KMSBatchDecryptResultItemResponse, 0, len(resp.Results))
	for _, result := range resp.Results {
		item := KMSBatchDecryptResultItemResponse{
			KeyVersion: result.KeyVersion,
			Error:      result.Error,
		}
		if len(result.Plaintext) > 0 {
			item.Plaintext = base64.StdEncoding.EncodeToString(result.Plaintext)
		}
		results = append(results, item)
	}

	apiResp := KMSBatchDecryptResponse{
		KeyID:        resp.KeyID,
		Results:      results,
		SuccessCount: resp.SuccessCount,
		FailureCount: resp.FailureCount,
		Timestamp:    resp.Timestamp,
	}

	h.logger.Info("Batch decrypt completed", "key_id", req.KeyID, "success_count", resp.SuccessCount, "failure_count", resp.FailureCount)
	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleRewrap handles POST /api/v1/kms/rewrap
func (h *KMSHandlers) handleRewrap(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSRewrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.SourceKeyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "source_key_id"})
		return
	}

	if req.DestinationKeyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "destination_key_id"})
		return
	}

	if req.Ciphertext == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "ciphertext"})
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "ciphertext", Cause: err})
		return
	}

	var sourceContext []byte
	if req.SourceContext != "" {
		sourceContext, err = base64.StdEncoding.DecodeString(req.SourceContext)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "source_context", Cause: err})
			return
		}
	}

	var destContext []byte
	if req.DestContext != "" {
		destContext, err = base64.StdEncoding.DecodeString(req.DestContext)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "dest_context", Cause: err})
			return
		}
	}

	var sourceNonce []byte
	if req.SourceNonce != "" {
		sourceNonce, err = base64.StdEncoding.DecodeString(req.SourceNonce)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "source_nonce", Cause: err})
			return
		}
	}

	serviceReq := &KMSRewrapServiceRequest{
		SourceKeyID:      req.SourceKeyID,
		DestinationKeyID: req.DestinationKeyID,
		Ciphertext:       ciphertext,
		SourceContext:    sourceContext,
		DestContext:      destContext,
		SourceNonce:      sourceNonce,
		SourceKeyVersion: req.SourceKeyVersion,
	}

	resp, err := h.service.Rewrap(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to rewrap", "error", err, "source_key_id", req.SourceKeyID, "dest_key_id", req.DestinationKeyID)
		h.writeKMSError(w, "rewrap", err)
		return
	}

	apiResp := KMSRewrapResponse{
		SourceKeyID:      resp.SourceKeyID,
		DestinationKeyID: resp.DestinationKeyID,
		SourceKeyVersion: resp.SourceKeyVersion,
		DestKeyVersion:   resp.DestKeyVersion,
		Ciphertext:       base64.StdEncoding.EncodeToString(resp.Ciphertext),
		Timestamp:        resp.Timestamp,
	}
	if len(resp.Nonce) > 0 {
		apiResp.Nonce = base64.StdEncoding.EncodeToString(resp.Nonce)
	}

	h.logger.Info("Rewrap completed", "source_key_id", req.SourceKeyID, "dest_key_id", req.DestinationKeyID)
	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleSign handles POST /api/v1/kms/sign
func (h *KMSHandlers) handleSign(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.KeyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "key_id"})
		return
	}

	if req.Message == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "message"})
		return
	}

	message, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "message", Cause: err})
		return
	}

	serviceReq := &KMSSignServiceRequest{
		KeyID:         req.KeyID,
		Message:       message,
		HashAlgorithm: req.HashAlgorithm,
		PreHashed:     req.PreHashed,
	}

	resp, err := h.service.Sign(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to sign", "error", err, "key_id", req.KeyID)
		h.writeKMSError(w, "sign", err)
		return
	}

	apiResp := KMSSignResponse{
		KeyID:         resp.KeyID,
		KeyVersion:    resp.KeyVersion,
		Signature:     base64.StdEncoding.EncodeToString(resp.Signature),
		HashAlgorithm: resp.HashAlgorithm,
		Timestamp:     resp.Timestamp,
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleVerify handles POST /api/v1/kms/verify
func (h *KMSHandlers) handleVerify(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.KeyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "key_id"})
		return
	}

	if req.Message == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "message"})
		return
	}

	if req.Signature == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "signature"})
		return
	}

	message, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "message", Cause: err})
		return
	}

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "signature", Cause: err})
		return
	}

	serviceReq := &KMSVerifyServiceRequest{
		KeyID:         req.KeyID,
		Message:       message,
		Signature:     signature,
		HashAlgorithm: req.HashAlgorithm,
		KeyVersion:    req.KeyVersion,
	}

	resp, err := h.service.Verify(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to verify", "error", err, "key_id", req.KeyID)
		h.writeKMSError(w, "verify", err)
		return
	}

	apiResp := KMSVerifyResponse{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  resp.Timestamp,
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleHash handles POST /api/v1/kms/hash
func (h *KMSHandlers) handleHash(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSHashRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.Data == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "data"})
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "data", Cause: err})
		return
	}

	serviceReq := &KMSHashServiceRequest{
		Data:      data,
		Algorithm: req.Algorithm,
	}

	resp, err := h.service.Hash(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to hash", "error", err)
		h.writeKMSError(w, "hash", err)
		return
	}

	apiResp := KMSHashResponse{
		Algorithm: resp.Algorithm,
		Hash:      base64.StdEncoding.EncodeToString(resp.Hash),
		Timestamp: resp.Timestamp,
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleHMAC handles POST /api/v1/kms/hmac
func (h *KMSHandlers) handleHMAC(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSHMACRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.KeyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "key_id"})
		return
	}

	if req.Message == "" {
		h.writeError(w, http.StatusBadRequest, ErrKMSMissingRequiredField{Field: "message"})
		return
	}

	message, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBase64{Field: "message", Cause: err})
		return
	}

	serviceReq := &KMSHMACServiceRequest{
		KeyID:         req.KeyID,
		Message:       message,
		HashAlgorithm: req.HashAlgorithm,
	}

	resp, err := h.service.HMAC(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to generate HMAC", "error", err, "key_id", req.KeyID)
		h.writeKMSError(w, "hmac", err)
		return
	}

	apiResp := KMSHMACResponse{
		KeyID:         resp.KeyID,
		KeyVersion:    resp.KeyVersion,
		HMAC:          base64.StdEncoding.EncodeToString(resp.HMAC),
		HashAlgorithm: resp.HashAlgorithm,
		Timestamp:     resp.Timestamp,
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// handleRandom handles POST /api/v1/kms/random
func (h *KMSHandlers) handleRandom(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	var req KMSRandomRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrKMSRequestBodyInvalid{Reason: err.Error()})
		return
	}

	if req.NumBytes <= 0 {
		h.writeError(w, http.StatusBadRequest, ErrInvalidNumBytes{NumBytes: req.NumBytes, Reason: "must be greater than 0"})
		return
	}

	if req.NumBytes > kmsMaxRandomBytes {
		h.writeError(w, http.StatusBadRequest, ErrInvalidNumBytes{NumBytes: req.NumBytes, Reason: "exceeds maximum allowed (1MB)"})
		return
	}

	serviceReq := &KMSGenerateRandomServiceRequest{
		NumBytes: req.NumBytes,
	}

	resp, err := h.service.GenerateRandom(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to generate random bytes", "error", err)
		h.writeKMSError(w, "random", err)
		return
	}

	apiResp := KMSRandomResponse{
		RandomBytes: base64.StdEncoding.EncodeToString(resp.RandomBytes),
		Timestamp:   resp.Timestamp,
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// =============================================================================
// Status Handler
// =============================================================================

// handleBackendStatus handles GET /api/v1/kms/status
func (h *KMSHandlers) handleBackendStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), kmsRequestTimeout)
	defer cancel()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrKMSServiceNotAvailable{})
		return
	}

	resp, err := h.service.BackendStatus(ctx)
	if err != nil {
		h.logger.Error("Failed to get backend status", "error", err)
		h.writeKMSError(w, "backend_status", err)
		return
	}

	apiResp := KMSBackendStatusResponse{
		BackendType:  resp.BackendType,
		Status:       resp.Status,
		Device:       resp.Device,
		Region:       resp.Region,
		KeyID:        resp.KeyID,
		PCRBanks:     resp.PcrBanks,
		PCRRegisters: resp.PcrRegisters,
		Capabilities: resp.Capabilities,
		Timestamp:    resp.Timestamp,
	}

	h.writeJSON(w, http.StatusOK, apiResp)
}

// =============================================================================
// Helper Methods
// =============================================================================

// getPaginationParams parses pagination parameters from the request.
func (h *KMSHandlers) getPaginationParams(r *http.Request) (int32, string) {
	limit := kmsDefaultLimit
	cursor := ""

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.ParseInt(l, 10, 32); err == nil {
			limit = int32(parsed)
			if limit > kmsMaxLimit {
				limit = kmsMaxLimit
			}
			if limit < 1 {
				limit = kmsDefaultLimit
			}
		}
	}

	if c := r.URL.Query().Get("cursor"); c != "" {
		cursor = c
	}

	return limit, cursor
}

// keySpecRequestToService converts API request to service format.
func (h *KMSHandlers) keySpecRequestToService(spec *KMSKeySpecRequest) *KMSKeySpec {
	if spec == nil {
		return nil
	}

	usage := make([]int32, len(spec.Usage))
	for i, u := range spec.Usage {
		usage[i] = h.stringToKeyUsage(u)
	}

	return &KMSKeySpec{
		Algorithm:          h.stringToKeyAlgorithm(spec.Algorithm),
		KeySize:            spec.KeySize,
		Usage:              usage,
		Exportable:         spec.Exportable,
		DeletionProtection: spec.DeletionProtection,
	}
}

// keyHandleToResponse converts service key handle to API response.
func (h *KMSHandlers) keyHandleToResponse(handle *KMSKeyHandle) *KMSKeyHandleResponse {
	if handle == nil {
		return nil
	}
	return &KMSKeyHandleResponse{
		KeyID:     handle.KeyID,
		Version:   handle.Version,
		Algorithm: handle.Algorithm,
		Status:    handle.Status,
		CreatedAt: handle.CreatedAt,
	}
}

// keyMetadataToResponse converts service key metadata to API response.
func (h *KMSHandlers) keyMetadataToResponse(metadata *KMSKeyMetadata) *KMSKeyMetadataResponse {
	if metadata == nil {
		return nil
	}
	return &KMSKeyMetadataResponse{
		KeyID:              metadata.KeyID,
		Name:               metadata.Name,
		Description:        metadata.Description,
		Algorithm:          metadata.Algorithm,
		Status:             metadata.Status,
		Usage:              metadata.Usage,
		Version:            metadata.Version,
		Exportable:         metadata.Exportable,
		DeletionProtection: metadata.DeletionProtection,
		CreatedAt:          metadata.CreatedAt,
		UpdatedAt:          metadata.UpdatedAt,
		LastUsedAt:         metadata.LastUsedAt,
		Tags:               metadata.Tags,
		Owner:              metadata.Owner,
	}
}

// stringToKeyAlgorithm converts string algorithm to int32.
func (h *KMSHandlers) stringToKeyAlgorithm(s string) int32 {
	switch s {
	case "AES-128-GCM":
		return 1
	case "AES-192-GCM":
		return 2
	case "AES-256-GCM":
		return 3
	case "CHACHA20-POLY1305":
		return 4
	case "XCHACHA20-POLY1305":
		return 5
	case "RSA-2048":
		return 10
	case "RSA-3072":
		return 11
	case "RSA-4096":
		return 12
	case "ECDSA-P256":
		return 20
	case "ECDSA-P384":
		return 21
	case "ECDSA-P521":
		return 22
	case "ED25519":
		return 30
	case "ED448":
		return 31
	case "X25519":
		return 40
	case "X448":
		return 41
	case "HMAC-SHA256":
		return 50
	case "HMAC-SHA384":
		return 51
	case "HMAC-SHA512":
		return 52
	default:
		return 0
	}
}

// stringToKeyUsage converts string usage to int32.
func (h *KMSHandlers) stringToKeyUsage(s string) int32 {
	switch s {
	case "ENCRYPT":
		return 1
	case "DECRYPT":
		return 2
	case "SIGN":
		return 3
	case "VERIFY":
		return 4
	case "WRAP_KEY":
		return 5
	case "DERIVE_KEY":
		return 6
	case "GENERATE_MAC":
		return 7
	case "VERIFY_MAC":
		return 8
	default:
		return 0
	}
}

// writeJSON writes a JSON response.
func (h *KMSHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *KMSHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// writeKMSError answers a failed KMS operation with the HTTP status for its
// error's class, as the shared classifier names it; an error that names no
// class is 500.
func (h *KMSHandlers) writeKMSError(w http.ResponseWriter, operation string, err error) {
	// A batch with some failed items is a partial success, not an error class.
	httpStatus := errclass.HTTPStatus(err)
	var batchErr ErrKMSBatchOperationFailed
	if errors.As(err, &batchErr) {
		httpStatus = http.StatusMultiStatus
	}

	h.writeError(w, httpStatus, ErrKMSHandlerOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}
