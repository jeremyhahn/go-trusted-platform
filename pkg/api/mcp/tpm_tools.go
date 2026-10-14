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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"google.golang.org/grpc/status"
)

// =============================================================================
// TPM Error Types
// =============================================================================

// TPMError represents a physical TPM operation error.
type TPMError struct {
	Code    string
	Message string
}

func (e *TPMError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *TPMError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
}

// ErrTPMServiceUnavailable indicates the TPM service is not available.
var ErrTPMServiceUnavailable = &TPMError{
	Code:    "TPM_SERVICE_UNAVAILABLE",
	Message: "TPM service is not available",
}

// ErrTPMNonceRequired indicates a nonce is required.
var ErrTPMNonceRequired = &TPMError{
	Code:    "TPM_NONCE_REQUIRED",
	Message: "nonce is required",
}

// ErrTPMInvalidNonce indicates an invalid nonce was provided.
var ErrTPMInvalidNonce = &TPMError{
	Code:    "TPM_INVALID_NONCE",
	Message: "invalid nonce encoding",
}

// ErrTPMDataRequired indicates data is required.
var ErrTPMDataRequired = &TPMError{
	Code:    "TPM_DATA_REQUIRED",
	Message: "data is required",
}

// ErrTPMInvalidData indicates invalid data was provided.
var ErrTPMInvalidData = &TPMError{
	Code:    "TPM_INVALID_DATA",
	Message: "invalid data encoding",
}

// ErrTPMSealedDataRequired indicates sealed data is required.
var ErrTPMSealedDataRequired = &TPMError{
	Code:    "TPM_SEALED_DATA_REQUIRED",
	Message: "sealed_data is required",
}

// ErrTPMInvalidSealedData indicates invalid sealed data was provided.
var ErrTPMInvalidSealedData = &TPMError{
	Code:    "TPM_INVALID_SEALED_DATA",
	Message: "invalid sealed_data encoding",
}

// ErrTPMCNRequired indicates a common name is required.
var ErrTPMCNRequired = &TPMError{
	Code:    "TPM_CN_REQUIRED",
	Message: "common name (cn) is required",
}

// ErrTPMCertificateRequired indicates a certificate is required.
var ErrTPMCertificateRequired = &TPMError{
	Code:    "TPM_CERTIFICATE_REQUIRED",
	Message: "certificate data is required",
}

// ErrTPMInvalidCertificate indicates invalid certificate data was provided.
var ErrTPMInvalidCertificate = &TPMError{
	Code:    "TPM_INVALID_CERTIFICATE",
	Message: "invalid certificate encoding",
}

// ErrTPMCredentialBlobRequired indicates a credential blob is required.
var ErrTPMCredentialBlobRequired = &TPMError{
	Code:    "TPM_CREDENTIAL_BLOB_REQUIRED",
	Message: "credential_blob is required",
}

// ErrTPMEncryptedSecretRequired indicates an encrypted secret is required.
var ErrTPMEncryptedSecretRequired = &TPMError{
	Code:    "TPM_ENCRYPTED_SECRET_REQUIRED",
	Message: "encrypted_secret is required",
}

// ErrTPMInvalidHandle indicates a persistent-handle argument could not
// be read as a 32-bit value. It is an error rather than a silent zero
// because zero is itself a meaningful handle (the SSRK): defaulting a
// malformed handle would answer with a key the caller did not ask for,
// which is the defect #475 exists to remove.
var ErrTPMInvalidHandle = &TPMError{
	Code:    "TPM_INVALID_HANDLE",
	Message: "invalid persistent handle: expected a 32-bit value such as 0x81000002",
}

// ErrTPMInvalidBase64 indicates a base64 argument failed to decode.
var ErrTPMInvalidBase64 = &TPMError{
	Code:    "TPM_INVALID_BASE64",
	Message: "invalid base64 encoding",
}

// =============================================================================
// TPM Tool Registration
// =============================================================================

// registerTPMTools registers physical TPM MCP tools.
func (r *ToolRegistry) registerTPMTools() {
	// TPM Info
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_info",
		Description: "Get TPM device information including manufacturer, firmware version, and capabilities",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// TPM Provision
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_provision",
		Description: "Provision the TPM with owner authorization and create required keys (EK, SRK, IAK)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"owner_password": map[string]interface{}{
					"type":        "string",
					"description": "Owner password for TPM provisioning (optional, uses platform default if empty)",
				},
			},
		},
	})

	// TPM Clear
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_clear",
		Description: "Clear the TPM, removing all keys and resetting owner authorization",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"owner_password": map[string]interface{}{
					"type":        "string",
					"description": "Owner password for authorization (optional)",
				},
			},
		},
	})

	// Get EK
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_ek",
		Description: "Get the Endorsement Key (EK) public key and handle",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Get EK Certificate
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_ek_cert",
		Description: "Get the Endorsement Key (EK) certificate in DER format (base64-encoded)",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Import EK Certificate
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_ek_import_cert",
		Description: "Import an EK certificate into the TPM NV storage",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"certificate": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded DER certificate to import",
				},
			},
			"required": []string{"certificate"},
		},
	})

	// Create EK
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_ek_create",
		Description: "Create an Endorsement Key (EK) using the platform's configured algorithm",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Delete EK
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_ek_delete",
		Description: "Flush the Endorsement Key (EK) handle from the TPM",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Get SRK
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_srk",
		Description: "Get a Storage Root Key (SRK) public key and handle. Omit handle for the storage-hierarchy SSRK, or pass 0x81000002 for the platform-hierarchy PlatformSRK.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"handle": map[string]interface{}{
					"type":        "integer",
					"description": "Persistent handle naming the SRK: 2164260865 (0x81000001) SSRK, 2164260866 (0x81000002) PlatformSRK. Omitted or 0 means the SSRK.",
				},
			},
		},
	})

	// Create SRK
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_srk_create",
		Description: "Create a Storage Root Key (SRK) using the platform's configured algorithm",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Delete SRK
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_srk_delete",
		Description: "Flush the Storage Root Key (SRK) handle from the TPM",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Get IAK
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_iak",
		Description: "Get the Initial Attestation Key (IAK) public key and handle",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Create IAK
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_iak_create",
		Description: "Create an Initial Attestation Key (IAK) under the Endorsement Key hierarchy",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Delete IAK
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_iak_delete",
		Description: "Flush the Initial Attestation Key (IAK) handle from the TPM",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Quote
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_quote",
		Description: "Generate a TPM quote for remote attestation, signed by the attestation key. The TPM quotes SHA-256(nonce || channel_binding), where channel_binding (returned) is the TLS exporter of this connection; MCP over stdio is refused",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"nonce": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded nonce for freshness guarantee",
				},
				"pcrs": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "integer"},
					"description": "PCR indices to include in the quote (0-23)",
				},
			},
			"required": []string{"nonce"},
		},
	})

	// Verify Quote
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_verify_quote",
		Description: "Verify a TPM quote against the attestation key and expected PCR values",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"quote": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded quote data",
				},
				"signature": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded quote signature",
				},
				"nonce": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded nonce used during quoting",
				},
				"channel_binding": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded channel binding the quote was produced under; the quote must then carry SHA-256(nonce || channel_binding)",
				},
				"ak_public": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded PKIX DER public key of the attestation key that signed the quote; omit it to verify against the platform IAK",
				},
				"signature_algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Scheme the quote declares, as platform_tpm_quote returned it (e.g. SHA256-RSAPSS); an absent or unknown scheme fails verification",
				},
			},
			"required": []string{"quote", "signature", "nonce", "signature_algorithm"},
		},
	})

	// Read PCRs
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_pcrs",
		Description: "Read Platform Configuration Register (PCR) values from the TPM",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"indices": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "integer"},
					"description": "PCR indices to read (0-23). If empty, reads all 24 PCRs.",
				},
			},
		},
	})

	// Extend PCR
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_pcr_extend",
		Description: "Extend a PCR with measurement data (hash is computed by the TPM)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pcr_index": map[string]interface{}{
					"type":        "integer",
					"description": "PCR index to extend (0-23)",
				},
				"data": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded data to extend into the PCR",
				},
				"hash_alg": map[string]interface{}{
					"type":        "string",
					"description": "PCR bank to extend: sha1, sha256, sha384 or sha512 (default sha256)",
				},
			},
			"required": []string{"pcr_index", "data"},
		},
	})

	// Event Log
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_eventlog",
		Description: "Retrieve the TPM event log (TCG PC Client format)",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Capabilities
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_capabilities",
		Description: "Get TPM fixed properties and capabilities (manufacturer, algorithms, key sizes)",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Random
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_random",
		Description: "Generate cryptographically secure random bytes from the TPM hardware RNG",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"num_bytes": map[string]interface{}{
					"type":        "integer",
					"description": "Number of random bytes to generate (1-1024, default: 32)",
					"default":     32,
				},
			},
		},
	})

	// Seal
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_seal",
		Description: "Seal data to the TPM, optionally binding to PCR state",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"data": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded data to seal",
				},
				"pcrs": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "integer"},
					"description": "PCR indices for sealing policy (0-23)",
				},
			},
			"required": []string{"data"},
		},
	})

	// Unseal
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_unseal",
		Description: "Unseal data from the TPM (requires matching PCR state if sealed with PCR policy)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"cn": map[string]interface{}{
					"type":        "string",
					"description": "Common name (key ID) of the sealed object to unseal",
				},
			},
			"required": []string{"cn"},
		},
	})

	// Certify
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_certify",
		Description: "Certify a TPM key using the attestation key, proving it resides in the TPM",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_handle": map[string]interface{}{
					"type":        "integer",
					"description": "Handle of the key to certify",
				},
			},
			"required": []string{"key_handle"},
		},
	})

	// NV List
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_nv_list",
		Description: "List all defined NVRAM indices in the TPM",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// NV Read
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_nv_read",
		Description: "Read data from a TPM NVRAM index",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"index": map[string]interface{}{
					"type":        "integer",
					"description": "NVRAM index to read from",
				},
				"size": map[string]interface{}{
					"type":        "integer",
					"description": "Number of bytes to read (optional, reads entire index if omitted)",
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"description": "Byte offset to read from (default 0)",
				},
				"password": map[string]interface{}{
					"type":        "string",
					"description": "Authorization password for the index or hierarchy its attributes select (optional)",
				},
			},
			"required": []string{"index"},
		},
	})

	// NV Write
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_nv_write",
		Description: "Write data to a TPM NVRAM index",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"index": map[string]interface{}{
					"type":        "integer",
					"description": "NVRAM index to write to",
				},
				"data": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded data to write",
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"description": "Byte offset to write at (default 0)",
				},
				"password": map[string]interface{}{
					"type":        "string",
					"description": "Authorization password for the index or hierarchy its attributes select (optional)",
				},
			},
			"required": []string{"index", "data"},
		},
	})

	// NV Delete
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_nv_delete",
		Description: "Undefine (delete) a TPM NVRAM index",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"index": map[string]interface{}{
					"type":        "integer",
					"description": "NVRAM index to undefine",
				},
				"parent_password": map[string]interface{}{
					"type":        "string",
					"description": "Owner hierarchy password (optional)",
				},
			},
			"required": []string{"index"},
		},
	})

	// Platform Attributes
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_platform",
		Description: "Get platform-level TPM attributes including configuration, simulator status, and key hierarchy",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})
	// MakeCredential
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_make_credential",
		Description: "Create a TPM2_MakeCredential challenge. Provide ak_name (base64) for the local-EK path, or ek_cert+iak_pub (base64) for the verifier path. secret (base64) is optional.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ak_name": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded AK name (local-EK path)",
				},
				"secret": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded secret to wrap (optional; random if omitted)",
				},
				"ek_cert": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded DER EK certificate (verifier path)",
				},
				"iak_pub": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded IAK public area (verifier path)",
				},
			},
		},
	})

	// ActivateCredential
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tpm_activate_credential",
		Description: "Activate a TPM2_MakeCredential challenge and recover the wrapped secret",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"credential_blob": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded credential blob",
				},
				"encrypted_secret": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded encrypted secret",
				},
			},
			"required": []interface{}{"credential_blob", "encrypted_secret"},
		},
	})

}
