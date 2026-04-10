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

// ErrKMSBundleNameRequired indicates a bundle name is required.
var ErrKMSBundleNameRequired = &KMSError{
	Code:    "KMS_BUNDLE_NAME_REQUIRED",
	Message: "bundle name is required",
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
					"description": "Key usage types (ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP_KEY, DERIVE_KEY)",
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
			"required": []string{"name", "algorithm"},
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
					"type":        "integer",
					"description": "Export format (0=PEM, 1=DER, 2=JWK)",
					"default":     0,
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
					"type":        "integer",
					"description": "Hash algorithm (0=SHA256, 1=SHA384, 2=SHA512)",
					"default":     0,
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

// registerKMSBundleTools registers KMS key bundle tools.
func (r *ToolRegistry) registerKMSBundleTools() {
	r.addTool(ToolDefinition{
		Name:        "kms_create_key_bundle",
		Description: "Create a key bundle containing related keys for a specific purpose",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Primary key ID for the bundle",
				},
				"bundle_name": map[string]interface{}{
					"type":        "string",
					"description": "Name for the key bundle",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "Description of the key bundle purpose",
				},
			},
			"required": []string{"key_id", "bundle_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "kms_list_key_bundles",
		Description: "List key bundles with optional filtering by key ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Filter bundles by key ID",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of bundles to return",
					"default":     50,
				},
				"cursor": map[string]interface{}{
					"type":        "string",
					"description": "Pagination cursor",
				},
			},
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
