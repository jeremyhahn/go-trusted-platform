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

package mcp

import (
	"fmt"
)

// =============================================================================
// KMS Error Types
// =============================================================================

// KMSError represents a KMS operation error.
type KMSError struct {
	Code    string
	Message string
}

func (e *KMSError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ErrKMSServiceUnavailable indicates the KMS service is not available.
var ErrKMSServiceUnavailable = &KMSError{
	Code:    "KMS_SERVICE_UNAVAILABLE",
	Message: "KMS service is not available",
}

// ErrKMSKeyIDRequired indicates a key ID is required.
var ErrKMSKeyIDRequired = &KMSError{
	Code:    "KMS_KEY_ID_REQUIRED",
	Message: "key ID is required",
}

// ErrKMSKeyNameRequired indicates a key name is required.
var ErrKMSKeyNameRequired = &KMSError{
	Code:    "KMS_KEY_NAME_REQUIRED",
	Message: "key name is required",
}

// ErrKMSAlgorithmRequired indicates an algorithm is required.
var ErrKMSAlgorithmRequired = &KMSError{
	Code:    "KMS_ALGORITHM_REQUIRED",
	Message: "key algorithm is required",
}

// ErrKMSMessageRequired indicates a message is required.
var ErrKMSMessageRequired = &KMSError{
	Code:    "KMS_MESSAGE_REQUIRED",
	Message: "message is required",
}

// ErrKMSSignatureRequired indicates a signature is required.
var ErrKMSSignatureRequired = &KMSError{
	Code:    "KMS_SIGNATURE_REQUIRED",
	Message: "signature is required",
}

// ErrKMSPlaintextRequired indicates plaintext is required.
var ErrKMSPlaintextRequired = &KMSError{
	Code:    "KMS_PLAINTEXT_REQUIRED",
	Message: "plaintext is required",
}

// ErrKMSCiphertextRequired indicates ciphertext is required.
var ErrKMSCiphertextRequired = &KMSError{
	Code:    "KMS_CIPHERTEXT_REQUIRED",
	Message: "ciphertext is required",
}

// ErrKMSKeyUsageRequired indicates at least one key usage is required.
var ErrKMSKeyUsageRequired = &KMSError{
	Code:    "KMS_KEY_USAGE_REQUIRED",
	Message: "at least one key usage is required",
}

// ErrKMSNumBytesRequired indicates a positive byte count is required.
var ErrKMSNumBytesRequired = &KMSError{
	Code:    "KMS_NUM_BYTES_REQUIRED",
	Message: "num_bytes must be a positive integer",
}

// =============================================================================
// KMS Tool Registration (called from tools.go registerKMSTools)
// =============================================================================

// registerKMSKeyManagementTools registers KMS key management tools.
func (r *ToolRegistry) registerKMSKeyManagementTools() {
	r.addTool(ToolDefinition{
		Name:        "kms_generate_key",
		Description: "Generate a new cryptographic key with specified algorithm and properties",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Name for the key (required)",
				},
				"algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Key algorithm (AES-128-GCM, AES-256-GCM, RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384, ED25519, etc.)",
				},
				"key_size": map[string]interface{}{
					"type":        "integer",
					"description": "Key size in bits (algorithm dependent)",
				},
				"usage": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Key usage types (ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP, UNWRAP, DERIVE, GENERATE_MAC, VERIFY_MAC); at least one is required unless provided via key_spec",
				},
				"key_spec": map[string]interface{}{
					"type":        "object",
					"description": "platform.v1 KMSKeySpec proto object (algorithm and usage as numeric enum values) as emitted by the SDK MCP transport adapter; flat fields take precedence when both are present",
				},
				"exportable": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether the key can be exported",
					"default":     false,
				},
				"deletion_protection": map[string]interface{}{
					"type":        "boolean",
					"description": "Prevent accidental key deletion",
					"default":     false,
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "Description of the key",
				},
				"tags": map[string]interface{}{
					"type":        "object",
					"description": "Key-value tags for the key",
				},
				"owner": map[string]interface{}{
					"type":        "string",
					"description": "Owner identifier for the key",
				},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_get_key",
		Description: "Get key details by ID including metadata and status",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to retrieve",
				},
				"version": map[string]interface{}{
					"type":        "integer",
					"description": "Specific key version (optional, defaults to current)",
				},
			},
			"required": []string{"key_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_list_keys",
		Description: "List all keys with optional filtering and pagination",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of keys to return",
					"default":     50,
				},
				"cursor": map[string]interface{}{
					"type":        "string",
					"description": "Pagination cursor for fetching next page",
				},
				"status": map[string]interface{}{
					"type":        "string",
					"description": "Filter by key status (ENABLED, DISABLED, PENDING_DELETION)",
				},
				"algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Filter by key algorithm",
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_delete_key",
		Description: "Delete a key with optional pending deletion window",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to delete",
				},
				"pending_window_days": map[string]interface{}{
					"type":        "integer",
					"description": "Number of days before permanent deletion (0 for immediate if allowed)",
					"default":     7,
				},
				"force": map[string]interface{}{
					"type":        "boolean",
					"description": "Force deletion bypassing deletion protection",
					"default":     false,
				},
			},
			"required": []string{"key_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_rotate_key",
		Description: "Rotate a key to generate a new version while optionally retaining the old version",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to rotate",
				},
				"retain_old_version": map[string]interface{}{
					"type":        "boolean",
					"description": "Keep old version available for decryption",
					"default":     true,
				},
			},
			"required": []string{"key_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_export_public_key",
		Description: "Export the public key material for asymmetric keys",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to export public key from",
				},
				"format": map[string]interface{}{
					"type":        "string",
					"description": "Export format for the public key",
					"enum":        []string{"PEM", "DER"},
					"default":     "PEM",
				},
				"version": map[string]interface{}{
					"type":        "integer",
					"description": "Specific key version (optional)",
				},
			},
			"required": []string{"key_id"},
		},
	})
}

// registerKMSCryptoTools registers KMS cryptographic operation tools.
func (r *ToolRegistry) registerKMSCryptoTools() {
	r.addTool(ToolDefinition{
		Name:        "kms_sign",
		Description: "Sign data using a private key to create a digital signature",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to use for signing",
				},
				"message": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded message to sign",
				},
				"hash_algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Hash algorithm (SHA256, SHA384, SHA512); numeric platform.v1 HashAlgorithm enum values are also accepted",
					"enum":        []string{"SHA256", "SHA384", "SHA512"},
					"default":     "SHA256",
				},
				"pre_hashed": map[string]interface{}{
					"type":        "boolean",
					"description": "When true, message is already a hash digest and is signed directly without hashing again",
				},
			},
			"required": []string{"key_id", "message"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_verify",
		Description: "Verify a digital signature using a public key",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to use for verification",
				},
				"message": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded original message",
				},
				"signature": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded signature to verify",
				},
				"hash_algorithm": map[string]interface{}{
					"type":        "integer",
					"description": "Hash algorithm used during signing",
					"default":     0,
				},
				"key_version": map[string]interface{}{
					"type":        "integer",
					"description": "Specific key version for verification",
				},
			},
			"required": []string{"key_id", "message", "signature"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_encrypt",
		Description: "Encrypt data using a symmetric or asymmetric key",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to use for encryption",
				},
				"plaintext": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded data to encrypt",
				},
				"context": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded additional authenticated data (AAD)",
				},
				"nonce": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded nonce/IV (optional, auto-generated if not provided)",
				},
			},
			"required": []string{"key_id", "plaintext"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_decrypt",
		Description: "Decrypt data using a symmetric or asymmetric key",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to use for decryption",
				},
				"ciphertext": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded data to decrypt",
				},
				"context": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded additional authenticated data (AAD)",
				},
				"nonce": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded nonce/IV used during encryption",
				},
				"key_version": map[string]interface{}{
					"type":        "integer",
					"description": "Specific key version for decryption",
				},
			},
			"required": []string{"key_id", "ciphertext"},
		},
	})
}

// registerKMSRandomTools registers the random byte generation tool.
func (r *ToolRegistry) registerKMSRandomTools() {
	r.addTool(ToolDefinition{
		Name:        "kms_random",
		Description: "Generate cryptographically secure random bytes (maximum 1024)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"num_bytes": map[string]interface{}{
					"type":        "integer",
					"description": "Number of random bytes to generate (1-1024)",
				},
			},
			"required": []string{"num_bytes"},
		},
	})
}

// registerKMSDataKeyTools registers data key tools (envelope encryption).
func (r *ToolRegistry) registerKMSDataKeyTools() {
	r.addTool(ToolDefinition{
		Name:        "kms_generate_data_key",
		Description: "Generate a data encryption key (DEK) for envelope encryption. Returns both plaintext and wrapped versions of the DEK.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "ID of the key encryption key (KEK) to wrap the DEK",
				},
				"algorithm": map[string]interface{}{
					"type":        "string",
					"description": "DEK algorithm (aes-128-gcm, aes-192-gcm, aes-256-gcm, chacha20-poly1305, xchacha20-poly1305)",
					"default":     "aes-256-gcm",
				},
				"context": map[string]interface{}{
					"type":        "string",
					"description": "Optional encryption context (AAD) for additional authentication",
				},
			},
			"required": []string{"key_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_generate_wrapped_data_key",
		Description: "Generate only a wrapped (encrypted) data encryption key. The plaintext DEK is never exposed - useful for pre-generating keys or key escrow.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "ID of the key encryption key (KEK) to wrap the DEK",
				},
				"algorithm": map[string]interface{}{
					"type":        "string",
					"description": "DEK algorithm (aes-128-gcm, aes-192-gcm, aes-256-gcm, chacha20-poly1305, xchacha20-poly1305)",
					"default":     "aes-256-gcm",
				},
				"context": map[string]interface{}{
					"type":        "string",
					"description": "Optional encryption context (AAD) for additional authentication",
				},
			},
			"required": []string{"key_id"},
		},
	})
}

// registerKMSLifecycleTools registers KMS key lifecycle tools (revoke,
// metadata, policy, algorithms, backend status).
func (r *ToolRegistry) registerKMSLifecycleTools() {
	r.addTool(ToolDefinition{
		Name:        "kms_revoke_key",
		Description: "Revoke a key, marking it as unusable for all cryptographic operations",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to revoke",
				},
				"reason": map[string]interface{}{
					"type":        "string",
					"description": "Reason for revocation (audit trail)",
				},
			},
			"required": []string{"key_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_get_key_metadata",
		Description: "Get key metadata (name, description, tags, timestamps) without exposing key material",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to retrieve metadata for",
				},
			},
			"required": []string{"key_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_update_key_metadata",
		Description: "Update mutable key metadata fields (name, description, tags)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to update",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "New display name (empty = no change)",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "New description (empty = no change)",
				},
				"tags": map[string]interface{}{
					"type":        "object",
					"description": "Tags to add or update",
				},
				"remove_tags": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Tag keys to remove",
				},
			},
			"required": []string{"key_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_get_key_policy",
		Description: "Get the access control policy for a key",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to retrieve the policy for",
				},
			},
			"required": []string{"key_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_set_key_policy",
		Description: "Set the access control policy for a key",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID to set the policy for",
				},
				"allowed_operations": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Permitted operations (ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP_KEY)",
				},
				"allowed_principals": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Authorized users/services",
				},
				"denied_principals": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Explicitly denied users/services",
				},
				"expires_at": map[string]interface{}{
					"type":        "integer",
					"description": "Unix timestamp when the policy expires (0 = never)",
				},
				"rotation_required": map[string]interface{}{
					"type":        "boolean",
					"description": "Require rotation before further use",
				},
				"max_usage_count": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of operations (0 = unlimited)",
				},
				"require_mfa": map[string]interface{}{
					"type":        "boolean",
					"description": "Require MFA for key usage",
				},
			},
			"required": []string{"key_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_supported_algorithms",
		Description: "List the cryptographic algorithms supported by the KMS backend",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_backend_status",
		Description: "Get health and capability information about the KMS backend",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})
}

// registerSecretsTools registers secrets management tools.
func (r *ToolRegistry) registerSecretsTools() {
	r.addTool(ToolDefinition{
		Name:        "secret_store",
		Description: "Store a secret with optional metadata. The value is encrypted at rest.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"secret_id": map[string]interface{}{
					"type":        "string",
					"description": "Secret identifier / path",
				},
				"data": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded secret data",
				},
				"metadata": map[string]interface{}{
					"type":        "object",
					"description": "Version-specific metadata key-value pairs",
				},
			},
			"required": []string{"secret_id", "data"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "secret_get",
		Description: "Retrieve a secret by ID, optionally at a specific version",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"secret_id": map[string]interface{}{
					"type":        "string",
					"description": "Secret identifier / path",
				},
				"version": map[string]interface{}{
					"type":        "integer",
					"description": "Specific version (0 = latest)",
				},
			},
			"required": []string{"secret_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "secret_list",
		Description: "List secrets (identifiers and metadata only, no secret data)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of secrets to return",
					"default":     50,
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "secret_delete",
		Description: "Delete a secret",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"secret_id": map[string]interface{}{
					"type":        "string",
					"description": "Secret identifier / path",
				},
			},
			"required": []string{"secret_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "secret_set_rotation_policy",
		Description: "Set the automatic rotation policy for a secret, including how many old versions to retain",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"secret_id": map[string]interface{}{
					"type":        "string",
					"description": "Secret identifier / path",
				},
				"enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable automatic rotation",
				},
				"interval_seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Rotation interval in seconds",
				},
				"retain_versions": map[string]interface{}{
					"type":        "integer",
					"description": "How many old versions to keep after rotation",
				},
			},
			"required": []string{"secret_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "secret_get_rotation_policy",
		Description: "Get the automatic rotation policy for a secret",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"secret_id": map[string]interface{}{
					"type":        "string",
					"description": "Secret identifier / path",
				},
			},
			"required": []string{"secret_id"},
		},
	})
}

// ErrSecretIDRequired indicates a secret ID is required.
var ErrSecretIDRequired = &KMSError{
	Code:    "SECRET_ID_REQUIRED",
	Message: "secret ID is required",
}

// ErrSecretDataRequired indicates secret data is required.
var ErrSecretDataRequired = &KMSError{
	Code:    "SECRET_DATA_REQUIRED",
	Message: "secret data is required",
}
