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

import "fmt"

// ErrKeyManagementClientNotInitialized is returned when the KeyManagement gRPC client is nil
type ErrKeyManagementClientNotInitialized struct{}

func (e ErrKeyManagementClientNotInitialized) Error() string {
	return "key management client not initialized"
}

// ErrCryptoClientNotInitialized is returned when the Crypto gRPC client is nil
type ErrCryptoClientNotInitialized struct{}

func (e ErrCryptoClientNotInitialized) Error() string {
	return "crypto client not initialized"
}

// ErrDEKManagementClientNotInitialized is returned when the DEKManagement gRPC client is nil
type ErrDEKManagementClientNotInitialized struct{}

func (e ErrDEKManagementClientNotInitialized) Error() string {
	return "DEK management client not initialized"
}

// ErrSecretsManagementClientNotInitialized is returned when the SecretsManagement gRPC client is nil
type ErrSecretsManagementClientNotInitialized struct{}

func (e ErrSecretsManagementClientNotInitialized) Error() string {
	return "secrets management client not initialized"
}

// ErrMissingKeyName is returned when key name is required but not provided
type ErrMissingKeyName struct{}

func (e ErrMissingKeyName) Error() string {
	return "key name is required"
}

// ErrMissingKeyID is returned when key ID is required but not provided
type ErrMissingKeyID struct{}

func (e ErrMissingKeyID) Error() string {
	return "key ID is required"
}

// ErrInvalidKeyID is returned when a key ID format is invalid
type ErrInvalidKeyID struct {
	KeyID  string
	Reason string
}

func (e ErrInvalidKeyID) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid key ID '%s': %s", e.KeyID, e.Reason)
	}
	return fmt.Sprintf("invalid key ID: %s", e.KeyID)
}

// ErrMissingDEKPath is returned when DEK path is required but not provided
type ErrMissingDEKPath struct{}

func (e ErrMissingDEKPath) Error() string {
	return "DEK path is required"
}

// ErrInvalidDEKPath is returned when a DEK path format is invalid
type ErrInvalidDEKPath struct {
	Path   string
	Reason string
}

func (e ErrInvalidDEKPath) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid DEK path '%s': %s", e.Path, e.Reason)
	}
	return fmt.Sprintf("invalid DEK path: %s", e.Path)
}

// ErrInvalidRequest is returned when the request is malformed or invalid
type ErrInvalidRequest struct {
	Reason string
}

func (e ErrInvalidRequest) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid request: %s", e.Reason)
	}
	return "invalid request"
}

// ErrInvalidRequestBody is returned when the request body cannot be parsed
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrMissingPlaintext is returned when plaintext data is required but not provided
type ErrMissingPlaintext struct{}

func (e ErrMissingPlaintext) Error() string {
	return "plaintext data is required"
}

// ErrMissingCiphertext is returned when ciphertext data is required but not provided
type ErrMissingCiphertext struct{}

func (e ErrMissingCiphertext) Error() string {
	return "ciphertext data is required"
}

// ErrKeyNotFound is returned when a key cannot be found
type ErrKeyNotFound struct {
	KeyID string
}

func (e ErrKeyNotFound) Error() string {
	return fmt.Sprintf("key not found: %s", e.KeyID)
}

// ErrDEKNotFound is returned when a DEK cannot be found
type ErrDEKNotFound struct {
	Path string
}

func (e ErrDEKNotFound) Error() string {
	return fmt.Sprintf("DEK not found: %s", e.Path)
}

// ErrInvalidAlgorithm is returned when an invalid algorithm is specified
type ErrInvalidAlgorithm struct {
	Algorithm string
	Reason    string
}

func (e ErrInvalidAlgorithm) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid algorithm '%s': %s", e.Algorithm, e.Reason)
	}
	return fmt.Sprintf("invalid algorithm: %s", e.Algorithm)
}

// ErrInvalidKeyStatus is returned when an invalid key status is specified
type ErrInvalidKeyStatus struct {
	Status string
	Reason string
}

func (e ErrInvalidKeyStatus) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid key status '%s': %s", e.Status, e.Reason)
	}
	return fmt.Sprintf("invalid key status: %s", e.Status)
}

// ErrMissingKeySpec is returned when key spec is required but not provided
type ErrMissingKeySpec struct{}

func (e ErrMissingKeySpec) Error() string {
	return "key spec is required"
}

// ErrInvalidPaginationParams is returned when pagination parameters are invalid
type ErrInvalidPaginationParams struct {
	Reason string
}

func (e ErrInvalidPaginationParams) Error() string {
	return fmt.Sprintf("invalid pagination parameters: %s", e.Reason)
}

// ErrOperationNotSupported is returned when an operation is not supported by the backend
type ErrOperationNotSupported struct {
	Operation string
	Reason    string
}

func (e ErrOperationNotSupported) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("operation '%s' not supported: %s", e.Operation, e.Reason)
	}
	return fmt.Sprintf("operation not supported: %s", e.Operation)
}

// ErrKeyMaterialRequired is returned when key material is required for import
type ErrKeyMaterialRequired struct{}

func (e ErrKeyMaterialRequired) Error() string {
	return "key material is required for import"
}

// ErrInvalidKeyVersion is returned when an invalid key version is specified
type ErrInvalidKeyVersion struct {
	Version uint64
	Reason  string
}

func (e ErrInvalidKeyVersion) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid key version %d: %s", e.Version, e.Reason)
	}
	return fmt.Sprintf("invalid key version: %d", e.Version)
}

// ErrMissingSecretName is returned when secret name is required but not provided
type ErrMissingSecretName struct{}

func (e ErrMissingSecretName) Error() string {
	return "secret name is required"
}

// ErrMissingSecretID is returned when secret ID is required but not provided
type ErrMissingSecretID struct{}

func (e ErrMissingSecretID) Error() string {
	return "secret ID is required"
}

// ErrSecretNotFound is returned when a secret cannot be found
type ErrSecretNotFound struct {
	SecretID string
}

func (e ErrSecretNotFound) Error() string {
	return fmt.Sprintf("secret not found: %s", e.SecretID)
}

// ErrMissingSecretData is returned when secret data is required but not provided
type ErrMissingSecretData struct{}

func (e ErrMissingSecretData) Error() string {
	return "secret data is required"
}

// ErrInvalidSecretVersion is returned when an invalid secret version is specified
type ErrInvalidSecretVersion struct {
	Version uint64
	Reason  string
}

func (e ErrInvalidSecretVersion) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid secret version %d: %s", e.Version, e.Reason)
	}
	return fmt.Sprintf("invalid secret version: %d", e.Version)
}

// ErrInvalidSecretStatus is returned when an invalid secret status is specified
type ErrInvalidSecretStatus struct {
	Status string
	Reason string
}

func (e ErrInvalidSecretStatus) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid secret status '%s': %s", e.Status, e.Reason)
	}
	return fmt.Sprintf("invalid secret status: %s", e.Status)
}

// ErrMissingTargetVersion is returned when target version is required for rollback
type ErrMissingTargetVersion struct{}

func (e ErrMissingTargetVersion) Error() string {
	return "target version is required for rollback"
}

// ErrInvalidRotationPolicy is returned when rotation policy is invalid
type ErrInvalidRotationPolicy struct {
	Reason string
}

func (e ErrInvalidRotationPolicy) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid rotation policy: %s", e.Reason)
	}
	return "invalid rotation policy"
}

// =============================================================================
// Crypto Error Types
// =============================================================================

// ErrMissingMessage is returned when message data is required but not provided
type ErrMissingMessage struct{}

func (e ErrMissingMessage) Error() string {
	return "message data is required"
}

// ErrMissingSignature is returned when signature is required but not provided
type ErrMissingSignature struct{}

func (e ErrMissingSignature) Error() string {
	return "signature is required"
}

// ErrMissingData is returned when data is required but not provided
type ErrMissingData struct{}

func (e ErrMissingData) Error() string {
	return "data is required"
}

// ErrMissingHMAC is returned when HMAC is required but not provided
type ErrMissingHMAC struct{}

func (e ErrMissingHMAC) Error() string {
	return "HMAC is required"
}

// ErrInvalidNumBytes is returned when an invalid number of bytes is requested
type ErrInvalidNumBytes struct {
	NumBytes int32
	Reason   string
}

func (e ErrInvalidNumBytes) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid number of bytes %d: %s", e.NumBytes, e.Reason)
	}
	return fmt.Sprintf("invalid number of bytes: %d", e.NumBytes)
}

// ErrInvalidHashAlgorithm is returned when an invalid hash algorithm is specified
type ErrInvalidHashAlgorithm struct {
	Algorithm string
	Reason    string
}

func (e ErrInvalidHashAlgorithm) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid hash algorithm '%s': %s", e.Algorithm, e.Reason)
	}
	return fmt.Sprintf("invalid hash algorithm: %s", e.Algorithm)
}

// ErrMissingBatchItems is returned when batch items are required but not provided
type ErrMissingBatchItems struct{}

func (e ErrMissingBatchItems) Error() string {
	return "batch items are required"
}

// ErrInvalidBatchOperation is returned when an invalid batch operation is specified
type ErrInvalidBatchOperation struct {
	Operation string
}

func (e ErrInvalidBatchOperation) Error() string {
	return fmt.Sprintf("invalid batch operation: %s (expected 'encrypt' or 'decrypt')", e.Operation)
}
