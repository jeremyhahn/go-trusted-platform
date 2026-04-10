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

package kms

import "time"

// PaginationParams contains common pagination parameters
type PaginationParams struct {
	Limit  int32  `json:"limit"`
	Cursor string `json:"cursor,omitempty"`
}

// PaginatedResponse contains common pagination response fields
type PaginatedResponse struct {
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
	TotalCount int32  `json:"total_count,omitempty"`
}

// SuccessResponse is a generic success response
type SuccessResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

// KeySpecRequest is the request format for key specification
type KeySpecRequest struct {
	Algorithm          string   `json:"algorithm"`
	KeySize            int32    `json:"key_size,omitempty"`
	Usage              []string `json:"usage,omitempty"`
	Exportable         bool     `json:"exportable,omitempty"`
	DeletionProtection bool     `json:"deletion_protection,omitempty"`
}

// GenerateKeyRequest is the request body for generating a key
type GenerateKeyRequest struct {
	KeySpec     KeySpecRequest    `json:"key_spec"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Owner       string            `json:"owner,omitempty"`
}

// ImportKeyRequest is the request body for importing a key
type ImportKeyRequest struct {
	KeyMaterial   []byte            `json:"key_material"`
	WrappingKeyID string            `json:"wrapping_key_id,omitempty"`
	KeySpec       KeySpecRequest    `json:"key_spec"`
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
}

// KeyHandleResponse represents a key handle in responses
type KeyHandleResponse struct {
	KeyID     string `json:"key_id"`
	Version   uint64 `json:"version"`
	Algorithm string `json:"algorithm"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
}

// RotationPolicyResponse represents rotation policy in responses
type RotationPolicyResponse struct {
	Enabled         bool  `json:"enabled"`
	IntervalSeconds int64 `json:"interval_seconds,omitempty"`
	NextRotation    int64 `json:"next_rotation,omitempty"`
	RetainVersions  int32 `json:"retain_versions,omitempty"`
	AutoRotate      bool  `json:"auto_rotate,omitempty"`
}

// KeyMetadataResponse represents key metadata in responses
type KeyMetadataResponse struct {
	KeyID              string                  `json:"key_id"`
	Name               string                  `json:"name"`
	Description        string                  `json:"description,omitempty"`
	Algorithm          string                  `json:"algorithm"`
	Status             string                  `json:"status"`
	Usage              []string                `json:"usage,omitempty"`
	Version            uint64                  `json:"version"`
	Exportable         bool                    `json:"exportable"`
	DeletionProtection bool                    `json:"deletion_protection"`
	CreatedAt          int64                   `json:"created_at"`
	UpdatedAt          int64                   `json:"updated_at,omitempty"`
	LastUsedAt         int64                   `json:"last_used_at,omitempty"`
	RotationPolicy     *RotationPolicyResponse `json:"rotation_policy,omitempty"`
	Tags               map[string]string       `json:"tags,omitempty"`
	Owner              string                  `json:"owner,omitempty"`
}

// GenerateKeyResponse is the response for key generation
type GenerateKeyResponse struct {
	Key       *KeyHandleResponse   `json:"key"`
	Metadata  *KeyMetadataResponse `json:"metadata"`
	Timestamp int64                `json:"timestamp"`
}

// ImportKeyResponse is the response for key import
type ImportKeyResponse struct {
	Key       *KeyHandleResponse   `json:"key"`
	Metadata  *KeyMetadataResponse `json:"metadata"`
	Timestamp int64                `json:"timestamp"`
}

// GetKeyResponse is the response for getting a key
type GetKeyResponse struct {
	Key       *KeyHandleResponse   `json:"key"`
	Metadata  *KeyMetadataResponse `json:"metadata"`
	Timestamp int64                `json:"timestamp"`
}

// ListKeysResponse is the response for listing keys
type ListKeysResponse struct {
	PaginatedResponse
	Keys      []KeyHandleResponse `json:"keys"`
	Timestamp int64               `json:"timestamp"`
}

// RotateKeyRequest is the request body for rotating a key
type RotateKeyRequest struct {
	RetainOldVersion bool `json:"retain_old_version,omitempty"`
}

// RotateKeyResponse is the response for key rotation
type RotateKeyResponse struct {
	KeyID      string `json:"key_id"`
	OldVersion uint64 `json:"old_version"`
	NewVersion uint64 `json:"new_version"`
	Timestamp  int64  `json:"timestamp"`
}

// DeleteKeyRequest is the request body for deleting a key
type DeleteKeyRequest struct {
	PendingWindowDays int32 `json:"pending_window_days,omitempty"`
	Force             bool  `json:"force,omitempty"`
}

// DeleteKeyResponse is the response for key deletion
type DeleteKeyResponse struct {
	KeyID        string `json:"key_id"`
	Status       string `json:"status"`
	DeletionDate int64  `json:"deletion_date,omitempty"`
	Timestamp    int64  `json:"timestamp"`
}

// UpdateKeyStatusRequest is the request body for updating key status
type UpdateKeyStatusRequest struct {
	Version uint64 `json:"version,omitempty"`
	Status  string `json:"status"`
}

// UpdateKeyStatusResponse is the response for key status update
type UpdateKeyStatusResponse struct {
	KeyID     string `json:"key_id"`
	Version   uint64 `json:"version"`
	Status    string `json:"status"`
	Timestamp int64  `json:"timestamp"`
}

// KeyVersionInfoResponse represents version info in responses
type KeyVersionInfoResponse struct {
	Version    uint64 `json:"version"`
	Status     string `json:"status"`
	Algorithm  string `json:"algorithm"`
	CreatedAt  int64  `json:"created_at"`
	DisabledAt int64  `json:"disabled_at,omitempty"`
}

// ListKeyVersionsResponse is the response for listing key versions
type ListKeyVersionsResponse struct {
	PaginatedResponse
	KeyID     string                   `json:"key_id"`
	Versions  []KeyVersionInfoResponse `json:"versions"`
	Timestamp int64                    `json:"timestamp"`
}

// ExportKeyRequest is the request body for exporting a key
type ExportKeyRequest struct {
	WrappingKeyID     string `json:"wrapping_key_id,omitempty"`
	WrappingAlgorithm string `json:"wrapping_algorithm,omitempty"`
	Format            string `json:"format,omitempty"`
	Version           uint64 `json:"version,omitempty"`
}

// ExportKeyResponse is the response for key export
type ExportKeyResponse struct {
	KeyID             string `json:"key_id"`
	Format            string `json:"format"`
	WrappingKeyID     string `json:"wrapping_key_id,omitempty"`
	WrappingAlgorithm string `json:"wrapping_algorithm,omitempty"`
	WrappedMaterial   []byte `json:"wrapped_material"`
	Version           uint64 `json:"version"`
	Timestamp         int64  `json:"timestamp"`
}

// RevokeKeyRequest is the request body for revoking a key
type RevokeKeyRequest struct {
	Reason string `json:"reason,omitempty"`
}

// RevokeKeyResponse is the response for key revocation
type RevokeKeyResponse struct {
	KeyID     string `json:"key_id"`
	Status    string `json:"status"`
	Timestamp int64  `json:"timestamp"`
}

// GetKeyMetadataResponse is the response for getting key metadata
type GetKeyMetadataResponse struct {
	Metadata  *KeyMetadataResponse `json:"metadata"`
	Timestamp int64                `json:"timestamp"`
}

// UpdateKeyMetadataRequest is the request body for updating key metadata
type UpdateKeyMetadataRequest struct {
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	RemoveTags  []string          `json:"remove_tags,omitempty"`
}

// UpdateKeyMetadataResponse is the response for key metadata update
type UpdateKeyMetadataResponse struct {
	Metadata  *KeyMetadataResponse `json:"metadata"`
	Timestamp int64                `json:"timestamp"`
}

// KeyPolicyRequest is the request format for key policy
type KeyPolicyRequest struct {
	AllowedOperations []string `json:"allowed_operations,omitempty"`
	AllowedPrincipals []string `json:"allowed_principals,omitempty"`
	DeniedPrincipals  []string `json:"denied_principals,omitempty"`
	ExpiresAt         int64    `json:"expires_at,omitempty"`
	RotationRequired  bool     `json:"rotation_required,omitempty"`
	MaxUsageCount     uint64   `json:"max_usage_count,omitempty"`
	RequireMFA        bool     `json:"require_mfa,omitempty"`
}

// SetKeyPolicyRequest is the request body for setting key policy
type SetKeyPolicyRequest struct {
	Policy KeyPolicyRequest `json:"policy"`
}

// SetKeyPolicyResponse is the response for setting key policy
type SetKeyPolicyResponse struct {
	KeyID         string `json:"key_id"`
	PolicyVersion uint64 `json:"policy_version"`
	Timestamp     int64  `json:"timestamp"`
}

// KeyPolicyResponse represents key policy in responses
type KeyPolicyResponse struct {
	KeyID             string   `json:"key_id"`
	Version           uint64   `json:"version"`
	AllowedOperations []string `json:"allowed_operations,omitempty"`
	AllowedPrincipals []string `json:"allowed_principals,omitempty"`
	DeniedPrincipals  []string `json:"denied_principals,omitempty"`
	ExpiresAt         int64    `json:"expires_at,omitempty"`
	RotationRequired  bool     `json:"rotation_required,omitempty"`
	MaxUsageCount     uint64   `json:"max_usage_count,omitempty"`
	RequireMFA        bool     `json:"require_mfa"`
	UpdatedAt         int64    `json:"updated_at,omitempty"`
}

// GetKeyPolicyResponse is the response for getting key policy
type GetKeyPolicyResponse struct {
	Policy    *KeyPolicyResponse `json:"policy"`
	Timestamp int64              `json:"timestamp"`
}

// ListAlgorithmsResponse is the response for listing supported algorithms
type ListAlgorithmsResponse struct {
	Algorithms []string `json:"algorithms"`
	Timestamp  int64    `json:"timestamp"`
}

// SetKeySafetyRequest is the request body for setting key safety limits
type SetKeySafetyRequest struct {
	MaxOperations  uint64 `json:"max_operations,omitempty"`
	MaxBytes       uint64 `json:"max_bytes,omitempty"`
	WarningPercent int32  `json:"warning_percent,omitempty"`
}

// SetKeySafetyResponse is the response for setting key safety
type SetKeySafetyResponse struct {
	KeyID     string `json:"key_id"`
	Timestamp int64  `json:"timestamp"`
}

// ClearKeySafetyResponse is the response for clearing key safety limits
type ClearKeySafetyResponse struct {
	KeyID     string `json:"key_id"`
	Timestamp int64  `json:"timestamp"`
}

// BackendStatusResponse is the response for backend status
type BackendStatusResponse struct {
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

// BackendTestResponse is the response for backend test
type BackendTestResponse struct {
	Success    bool   `json:"success"`
	DurationMs int64  `json:"duration_ms"`
	Message    string `json:"message,omitempty"`
	Timestamp  int64  `json:"timestamp"`
}

// =============================================================================
// Crypto Types
// =============================================================================

// EncryptRequest is the request body for encryption
type EncryptRequest struct {
	Plaintext []byte `json:"plaintext"`
	Context   []byte `json:"context,omitempty"`
	Nonce     []byte `json:"nonce,omitempty"`
}

// EncryptResponse is the response for encryption
type EncryptResponse struct {
	KeyID      string `json:"key_id"`
	KeyVersion uint64 `json:"key_version"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce,omitempty"`
	Timestamp  int64  `json:"timestamp"`
}

// DecryptRequest is the request body for decryption
type DecryptRequest struct {
	Ciphertext []byte `json:"ciphertext"`
	Context    []byte `json:"context,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty"`
}

// DecryptResponse is the response for decryption
type DecryptResponse struct {
	KeyID      string `json:"key_id"`
	KeyVersion uint64 `json:"key_version"`
	Plaintext  []byte `json:"plaintext"`
	Timestamp  int64  `json:"timestamp"`
}

// SignRequest is the request body for signing
type SignRequest struct {
	Message       []byte `json:"message"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
}

// SignResponse is the response for signing
type SignResponse struct {
	KeyID         string `json:"key_id"`
	KeyVersion    uint64 `json:"key_version"`
	Signature     []byte `json:"signature"`
	HashAlgorithm string `json:"hash_algorithm"`
	Timestamp     int64  `json:"timestamp"`
}

// VerifyRequest is the request body for signature verification
type VerifyRequest struct {
	Message       []byte `json:"message"`
	Signature     []byte `json:"signature"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	KeyVersion    uint64 `json:"key_version,omitempty"`
}

// VerifyResponse is the response for signature verification
type VerifyResponse struct {
	KeyID      string `json:"key_id"`
	KeyVersion uint64 `json:"key_version"`
	Valid      bool   `json:"valid"`
	Timestamp  int64  `json:"timestamp"`
}

// HashRequest is the request body for hashing
type HashRequest struct {
	Data      []byte `json:"data"`
	Algorithm string `json:"algorithm,omitempty"`
}

// HashResponse is the response for hashing
type HashResponse struct {
	Algorithm string `json:"algorithm"`
	Hash      []byte `json:"hash"`
	Timestamp int64  `json:"timestamp"`
}

// HMACRequest is the request body for HMAC generation
type HMACRequest struct {
	Message       []byte `json:"message"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
}

// HMACResponse is the response for HMAC generation
type HMACResponse struct {
	KeyID         string `json:"key_id"`
	KeyVersion    uint64 `json:"key_version"`
	HMAC          []byte `json:"hmac"`
	HashAlgorithm string `json:"hash_algorithm"`
	Timestamp     int64  `json:"timestamp"`
}

// VerifyHMACRequest is the request body for HMAC verification
type VerifyHMACRequest struct {
	Message       []byte `json:"message"`
	HMAC          []byte `json:"hmac"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	KeyVersion    uint64 `json:"key_version,omitempty"`
}

// VerifyHMACResponse is the response for HMAC verification
type VerifyHMACResponse struct {
	KeyID      string `json:"key_id"`
	KeyVersion uint64 `json:"key_version"`
	Valid      bool   `json:"valid"`
	Timestamp  int64  `json:"timestamp"`
}

// GenerateRandomRequest is the request body for random bytes generation
type GenerateRandomRequest struct {
	NumBytes int32 `json:"num_bytes"`
}

// GenerateRandomResponse is the response for random bytes generation
type GenerateRandomResponse struct {
	RandomBytes []byte `json:"random_bytes"`
	Timestamp   int64  `json:"timestamp"`
}

// RewrapRequest is the request body for rewrapping ciphertext
type RewrapRequest struct {
	Ciphertext []byte `json:"ciphertext"`
	Context    []byte `json:"context,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
}

// RewrapResponse is the response for rewrapping ciphertext
type RewrapResponse struct {
	KeyID         string `json:"key_id"`
	OldKeyVersion uint64 `json:"old_key_version"`
	NewKeyVersion uint64 `json:"new_key_version"`
	Ciphertext    []byte `json:"ciphertext"`
	Nonce         []byte `json:"nonce,omitempty"`
	Timestamp     int64  `json:"timestamp"`
}

// BatchEncryptItem represents a single item in a batch encrypt request
type BatchEncryptItem struct {
	Plaintext []byte `json:"plaintext"`
	Context   []byte `json:"context,omitempty"`
}

// BatchEncryptResult represents a single result in a batch encrypt response
type BatchEncryptResult struct {
	Ciphertext []byte `json:"ciphertext,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	Error      string `json:"error,omitempty"`
}

// BatchDecryptItem represents a single item in a batch decrypt request
type BatchDecryptItem struct {
	Ciphertext []byte `json:"ciphertext"`
	Context    []byte `json:"context,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
}

// BatchDecryptResult represents a single result in a batch decrypt response
type BatchDecryptResult struct {
	Plaintext []byte `json:"plaintext,omitempty"`
	Error     string `json:"error,omitempty"`
}

// BatchEncryptRequest is the request body for batch encryption
type BatchEncryptRequest struct {
	Items []BatchEncryptItem `json:"items"`
}

// BatchEncryptResponse is the response for batch encryption
type BatchEncryptResponse struct {
	KeyID      string               `json:"key_id"`
	KeyVersion uint64               `json:"key_version"`
	Results    []BatchEncryptResult `json:"results"`
	Timestamp  int64                `json:"timestamp"`
}

// BatchDecryptRequest is the request body for batch decryption
type BatchDecryptRequest struct {
	Items []BatchDecryptItem `json:"items"`
}

// BatchDecryptResponse is the response for batch decryption
type BatchDecryptResponse struct {
	KeyID     string               `json:"key_id"`
	Results   []BatchDecryptResult `json:"results"`
	Timestamp int64                `json:"timestamp"`
}

// BatchRequest is a unified batch request supporting both encrypt and decrypt operations
type BatchRequest struct {
	Operation    string             `json:"operation"`
	EncryptItems []BatchEncryptItem `json:"encrypt_items,omitempty"`
	DecryptItems []BatchDecryptItem `json:"decrypt_items,omitempty"`
}

// BatchResponse is a unified batch response
type BatchResponse struct {
	KeyID          string               `json:"key_id"`
	KeyVersion     uint64               `json:"key_version,omitempty"`
	EncryptResults []BatchEncryptResult `json:"encrypt_results,omitempty"`
	DecryptResults []BatchDecryptResult `json:"decrypt_results,omitempty"`
	Timestamp      int64                `json:"timestamp"`
}

// =============================================================================
// DEK Management Types
// =============================================================================

// DEKMetadataResponse represents DEK metadata in responses
type DEKMetadataResponse struct {
	Path           string `json:"path"`
	Algorithm      string `json:"algorithm"`
	Version        uint64 `json:"version"`
	Status         string `json:"status"`
	IsDefault      bool   `json:"is_default"`
	CreatedAt      int64  `json:"created_at"`
	RotatedAt      int64  `json:"rotated_at,omitempty"`
	UsageCount     uint64 `json:"usage_count"`
	BytesUsed      uint64 `json:"bytes_used"`
	MaxUsageCount  uint64 `json:"max_usage_count,omitempty"`
	MaxBytesUsed   uint64 `json:"max_bytes_used,omitempty"`
	WarningPercent int32  `json:"warning_percent,omitempty"`
	Description    string `json:"description,omitempty"`
	BackendType    string `json:"backend_type,omitempty"`
}

// CreateDEKRequest is the request body for creating a DEK
type CreateDEKRequest struct {
	Path           string `json:"path"`
	Algorithm      string `json:"algorithm,omitempty"`
	Description    string `json:"description,omitempty"`
	MaxOperations  uint64 `json:"max_operations,omitempty"`
	MaxBytes       uint64 `json:"max_bytes,omitempty"`
	WarningPercent int32  `json:"warning_percent,omitempty"`
}

// CreateDEKResponse is the response for DEK creation
type CreateDEKResponse struct {
	DEK       *DEKMetadataResponse `json:"dek"`
	Timestamp int64                `json:"timestamp"`
}

// GetDEKResponse is the response for getting a DEK
type GetDEKResponse struct {
	DEK       *DEKMetadataResponse `json:"dek"`
	Timestamp int64                `json:"timestamp"`
}

// ListDEKsResponse is the response for listing DEKs
type ListDEKsResponse struct {
	PaginatedResponse
	DEKs      []DEKMetadataResponse `json:"deks"`
	Timestamp int64                 `json:"timestamp"`
}

// RotateDEKRequest is the request body for rotating a DEK
type RotateDEKRequest struct {
	Background bool `json:"background,omitempty"`
}

// RotateDEKResponse is the response for DEK rotation
type RotateDEKResponse struct {
	Path       string `json:"path"`
	OldVersion uint64 `json:"old_version"`
	NewVersion uint64 `json:"new_version"`
	Timestamp  int64  `json:"timestamp"`
}

// DeleteDEKRequest is the request body for deleting a DEK
type DeleteDEKRequest struct {
	Force     bool   `json:"force,omitempty"`
	MigrateTo string `json:"migrate_to,omitempty"`
}

// DeleteDEKResponse is the response for DEK deletion
type DeleteDEKResponse struct {
	Path      string `json:"path"`
	Deleted   bool   `json:"deleted"`
	Timestamp int64  `json:"timestamp"`
}

// ReencryptionProgressResponse represents reencryption progress in responses
type ReencryptionProgressResponse struct {
	InProgress          bool  `json:"in_progress"`
	TotalKeys           int32 `json:"total_keys"`
	ProcessedKeys       int32 `json:"processed_keys"`
	FailedKeys          int32 `json:"failed_keys"`
	StartedAt           int64 `json:"started_at,omitempty"`
	EstimatedCompletion int64 `json:"estimated_completion,omitempty"`
}

// GetDEKStatusResponse is the response for getting DEK status
type GetDEKStatusResponse struct {
	DEK                  *DEKMetadataResponse          `json:"dek"`
	ReencryptionProgress *ReencryptionProgressResponse `json:"reencryption_progress,omitempty"`
	Timestamp            int64                         `json:"timestamp"`
}

// SetDefaultDEKResponse is the response for setting the default DEK
type SetDefaultDEKResponse struct {
	Path      string `json:"path"`
	Timestamp int64  `json:"timestamp"`
}

// SetDEKSafetyRequest is the request body for setting DEK safety limits
type SetDEKSafetyRequest struct {
	MaxOperations  uint64 `json:"max_operations,omitempty"`
	MaxBytes       uint64 `json:"max_bytes,omitempty"`
	WarningPercent int32  `json:"warning_percent,omitempty"`
}

// SetDEKSafetyResponse is the response for setting DEK safety
type SetDEKSafetyResponse struct {
	Path      string `json:"path"`
	Timestamp int64  `json:"timestamp"`
}

// ClearDEKSafetyResponse is the response for clearing DEK safety limits
type ClearDEKSafetyResponse struct {
	Path      string `json:"path"`
	Timestamp int64  `json:"timestamp"`
}

// timeToUnix converts a time.Time pointer to Unix timestamp
func timeToUnix(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}

// =============================================================================
// Secrets Management Types
// =============================================================================

// SecretRotationPolicyRequest is the request format for secret rotation policy
type SecretRotationPolicyRequest struct {
	Enabled         bool   `json:"enabled"`
	IntervalSeconds int64  `json:"interval_seconds,omitempty"`
	RetainVersions  int32  `json:"retain_versions,omitempty"`
	RotationLambda  string `json:"rotation_lambda,omitempty"`
}

// SecretRotationPolicyResponse represents secret rotation policy in responses
type SecretRotationPolicyResponse struct {
	Enabled         bool   `json:"enabled"`
	IntervalSeconds int64  `json:"interval_seconds,omitempty"`
	NextRotation    int64  `json:"next_rotation,omitempty"`
	RetainVersions  int32  `json:"retain_versions,omitempty"`
	RotationLambda  string `json:"rotation_lambda,omitempty"`
}

// SecretResponse represents a secret in responses
type SecretResponse struct {
	SecretID       string                        `json:"secret_id"`
	Name           string                        `json:"name"`
	Description    string                        `json:"description,omitempty"`
	CurrentVersion uint64                        `json:"current_version"`
	CreatedAt      int64                         `json:"created_at"`
	UpdatedAt      int64                         `json:"updated_at,omitempty"`
	RotationPolicy *SecretRotationPolicyResponse `json:"rotation_policy,omitempty"`
	Tags           map[string]string             `json:"tags,omitempty"`
	Owner          string                        `json:"owner,omitempty"`
}

// SecretVersionResponse represents a secret version in responses
type SecretVersionResponse struct {
	SecretID  string            `json:"secret_id"`
	Version   uint64            `json:"version"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt int64             `json:"created_at"`
	CreatedBy string            `json:"created_by,omitempty"`
	DeletedAt int64             `json:"deleted_at,omitempty"`
	ExpiresAt int64             `json:"expires_at,omitempty"`
}

// StoreSecretRequest is the request body for storing a secret
type StoreSecretRequest struct {
	SecretID    string            `json:"secret_id,omitempty"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Data        []byte            `json:"data"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	ExpiresAt   int64             `json:"expires_at,omitempty"`
	TenantID    string            `json:"tenant_id,omitempty"`
	KeyID       string            `json:"key_id,omitempty"`
	Algorithm   string            `json:"algorithm,omitempty"`
}

// StoreSecretResponse is the response for storing a secret
type StoreSecretResponse struct {
	SecretID  string `json:"secret_id"`
	Version   uint64 `json:"version"`
	Timestamp int64  `json:"timestamp"`
}

// GetSecretRequest is the request params for getting a secret
type GetSecretRequest struct {
	Version uint64 `json:"version,omitempty"`
}

// GetSecretResponse is the response for getting a secret
type GetSecretResponse struct {
	SecretID      string            `json:"secret_id"`
	Version       uint64            `json:"version"`
	Data          []byte            `json:"data"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     int64             `json:"created_at"`
	Timestamp     int64             `json:"timestamp"`
	Algorithm     string            `json:"algorithm,omitempty"`
	KeyIdentifier string            `json:"key_identifier,omitempty"`
}

// ListSecretsResponse is the response for listing secrets
type ListSecretsResponse struct {
	PaginatedResponse
	Secrets   []SecretResponse `json:"secrets"`
	Timestamp int64            `json:"timestamp"`
}

// DeleteSecretRequest is the request body for deleting a secret
type DeleteSecretRequest struct {
	PermanentlyDelete bool `json:"permanently_delete,omitempty"`
}

// DeleteSecretResponse is the response for deleting a secret
type DeleteSecretResponse struct {
	SecretID  string `json:"secret_id"`
	Deleted   bool   `json:"deleted"`
	Timestamp int64  `json:"timestamp"`
}

// GetSecretVersionResponse is the response for getting a specific secret version
type GetSecretVersionResponse struct {
	Version   *SecretVersionResponse `json:"version"`
	Data      []byte                 `json:"data"`
	Timestamp int64                  `json:"timestamp"`
}

// ListSecretVersionsResponse is the response for listing secret versions
type ListSecretVersionsResponse struct {
	PaginatedResponse
	Versions  []SecretVersionResponse `json:"versions"`
	Timestamp int64                   `json:"timestamp"`
}

// RollbackSecretRequest is the request body for rolling back a secret
type RollbackSecretRequest struct {
	TargetVersion uint64 `json:"target_version"`
}

// RollbackSecretResponse is the response for rolling back a secret
type RollbackSecretResponse struct {
	SecretID   string `json:"secret_id"`
	NewVersion uint64 `json:"new_version"`
	Timestamp  int64  `json:"timestamp"`
}

// RotateSecretRequest is the request body for rotating a secret
type RotateSecretRequest struct {
	NewData   []byte            `json:"new_data"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	TenantID  string            `json:"tenant_id,omitempty"`
	KeyID     string            `json:"key_id,omitempty"`
	Algorithm string            `json:"algorithm,omitempty"`
}

// RotateSecretResponse is the response for rotating a secret
type RotateSecretResponse struct {
	SecretID   string `json:"secret_id"`
	OldVersion uint64 `json:"old_version"`
	NewVersion uint64 `json:"new_version"`
	Timestamp  int64  `json:"timestamp"`
}

// UpdateSecretStatusRequest is the request body for updating secret status
type UpdateSecretStatusRequest struct {
	Status string `json:"status"`
}

// UpdateSecretStatusResponse is the response for updating secret status
type UpdateSecretStatusResponse struct {
	SecretID  string `json:"secret_id"`
	Status    string `json:"status"`
	Timestamp int64  `json:"timestamp"`
}

// SetSecretRotationPolicyRequest is the request body for setting rotation policy
type SetSecretRotationPolicyRequest struct {
	Policy SecretRotationPolicyRequest `json:"policy"`
}

// SetSecretRotationPolicyResponse is the response for setting rotation policy
type SetSecretRotationPolicyResponse struct {
	SecretID  string                        `json:"secret_id"`
	Policy    *SecretRotationPolicyResponse `json:"policy"`
	Timestamp int64                         `json:"timestamp"`
}

// GetSecretRotationPolicyResponse is the response for getting rotation policy
type GetSecretRotationPolicyResponse struct {
	SecretID  string                        `json:"secret_id"`
	Policy    *SecretRotationPolicyResponse `json:"policy"`
	Timestamp int64                         `json:"timestamp"`
}

// SecretDataResponse represents secret data in prefix operations
type SecretDataResponse struct {
	Data     map[string][]byte `json:"data,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Version  int64             `json:"version"`
}

// GetSecretsByPrefixResponse is the response for getting secrets by prefix
type GetSecretsByPrefixResponse struct {
	PaginatedResponse
	Secrets   map[string]SecretDataResponse `json:"secrets"`
	Timestamp int64                         `json:"timestamp"`
}
