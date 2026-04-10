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
// vTPM Error Types
// =============================================================================

// VTPMError represents a vTPM operation error.
type VTPMError struct {
	Code    string
	Message string
}

func (e *VTPMError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ErrVTPMServiceUnavailable indicates the vTPM service extension is not available.
var ErrVTPMServiceUnavailable = &VTPMError{
	Code:    "VTPM_SERVICE_UNAVAILABLE",
	Message: "vTPM service is not available",
}

// ErrVTPMBundleIDRequired indicates a bundle ID is required.
var ErrVTPMBundleIDRequired = &VTPMError{
	Code:    "VTPM_BUNDLE_ID_REQUIRED",
	Message: "bundle ID is required",
}

// ErrVTPMTemplateIDRequired indicates a template ID is required.
var ErrVTPMTemplateIDRequired = &VTPMError{
	Code:    "VTPM_TEMPLATE_ID_REQUIRED",
	Message: "template ID is required",
}

// ErrVTPMHostnameRequired indicates a hostname is required.
var ErrVTPMHostnameRequired = &VTPMError{
	Code:    "VTPM_HOSTNAME_REQUIRED",
	Message: "hostname is required",
}

// ErrVTPMNonceRequired indicates a nonce is required.
var ErrVTPMNonceRequired = &VTPMError{
	Code:    "VTPM_NONCE_REQUIRED",
	Message: "nonce is required",
}

// ErrVTPMInvalidNonce indicates an invalid nonce was provided.
var ErrVTPMInvalidNonce = &VTPMError{
	Code:    "VTPM_INVALID_NONCE",
	Message: "invalid nonce encoding",
}

// ErrVTPMDataRequired indicates data is required.
var ErrVTPMDataRequired = &VTPMError{
	Code:    "VTPM_DATA_REQUIRED",
	Message: "data is required",
}

// ErrVTPMInvalidData indicates invalid data was provided.
var ErrVTPMInvalidData = &VTPMError{
	Code:    "VTPM_INVALID_DATA",
	Message: "invalid data encoding",
}

// ErrVTPMSealedDataRequired indicates sealed data is required.
var ErrVTPMSealedDataRequired = &VTPMError{
	Code:    "VTPM_SEALED_DATA_REQUIRED",
	Message: "sealed_data is required",
}

// ErrVTPMInvalidSealedData indicates invalid sealed data was provided.
var ErrVTPMInvalidSealedData = &VTPMError{
	Code:    "VTPM_INVALID_SEALED_DATA",
	Message: "invalid sealed_data encoding",
}

// ErrVTPMInvalidPCRIndex indicates an invalid PCR index was provided.
var ErrVTPMInvalidPCRIndex = &VTPMError{
	Code:    "VTPM_INVALID_PCR_INDEX",
	Message: "invalid PCR index (must be 0-23)",
}

// =============================================================================
// vTPM Tool Registration
// =============================================================================

// registerVTPMBundleTools registers vTPM bundle-related MCP tools.
// This replaces the basic vTPM tools with full bundle/template API support.
func (r *ToolRegistry) registerVTPMBundleTools() {
	// Bundle CRUD operations
	r.addTool(ToolDefinition{
		Name:        "vtpm_bundle_create",
		Description: "Create a new vTPM bundle with EK certificate and optional Secure Boot keys",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"hostname": map[string]interface{}{
					"type":        "string",
					"description": "Hostname for the vTPM bundle (required)",
				},
				"ek_algorithm": map[string]interface{}{
					"type":        "string",
					"description": "EK algorithm (RSA or ECC, default: RSA)",
					"enum":        []string{"RSA", "ECC"},
					"default":     "RSA",
				},
				"secure_boot_enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable Secure Boot key generation and enrollment",
					"default":     false,
				},
				"labels": map[string]interface{}{
					"type":        "object",
					"description": "Custom metadata labels as key-value pairs",
				},
			},
			"required": []string{"hostname"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_bundle_get",
		Description: "Get detailed information about a vTPM bundle",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bundle_id": map[string]interface{}{
					"type":        "string",
					"description": "Bundle ID or hostname",
				},
			},
			"required": []string{"bundle_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_bundle_list",
		Description: "List all vTPM bundles with optional filters",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"mode": map[string]interface{}{
					"type":        "string",
					"description": "Filter by bundle mode (template, pre-assigned)",
				},
				"labels": map[string]interface{}{
					"type":        "object",
					"description": "Filter by label key-value pairs",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of bundles to return",
					"default":     50,
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"description": "Number of bundles to skip for pagination",
					"default":     0,
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_bundle_delete",
		Description: "Delete a vTPM bundle and all associated state",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bundle_id": map[string]interface{}{
					"type":        "string",
					"description": "Bundle ID to delete",
				},
			},
			"required": []string{"bundle_id"},
		},
	})

	// Template operations
	r.addTool(ToolDefinition{
		Name:        "vtpm_template_create",
		Description: "Create a reusable vTPM template (identity assigned at clone time)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"template_id": map[string]interface{}{
					"type":        "string",
					"description": "Unique template identifier (required)",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "Template description",
				},
				"ek_algorithm": map[string]interface{}{
					"type":        "string",
					"description": "EK algorithm (RSA or ECC, default: RSA)",
					"enum":        []string{"RSA", "ECC"},
					"default":     "RSA",
				},
				"secure_boot_enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable Secure Boot key generation and enrollment",
					"default":     false,
				},
			},
			"required": []string{"template_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_template_get",
		Description: "Get detailed information about a vTPM template",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"template_id": map[string]interface{}{
					"type":        "string",
					"description": "Template ID",
				},
			},
			"required": []string{"template_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_template_list",
		Description: "List all vTPM templates",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_template_delete",
		Description: "Delete a vTPM template",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"template_id": map[string]interface{}{
					"type":        "string",
					"description": "Template ID to delete",
				},
			},
			"required": []string{"template_id"},
		},
	})

	// TPM operations
	r.addTool(ToolDefinition{
		Name:        "vtpm_bundle_quote",
		Description: "Generate a TPM quote for attestation from a running vTPM bundle",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bundle_id": map[string]interface{}{
					"type":        "string",
					"description": "Bundle ID of the running vTPM",
				},
				"nonce": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded nonce for freshness (required)",
				},
				"pcrs": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "integer"},
					"description": "PCR indices to include in the quote (0-23)",
				},
			},
			"required": []string{"bundle_id", "nonce"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_bundle_pcr_read",
		Description: "Read a PCR value from a running vTPM bundle",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bundle_id": map[string]interface{}{
					"type":        "string",
					"description": "Bundle ID of the running vTPM",
				},
				"pcr_index": map[string]interface{}{
					"type":        "integer",
					"description": "PCR index to read (0-23)",
				},
			},
			"required": []string{"bundle_id", "pcr_index"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_bundle_pcr_extend",
		Description: "Extend a PCR with measurement data on a running vTPM bundle",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bundle_id": map[string]interface{}{
					"type":        "string",
					"description": "Bundle ID of the running vTPM",
				},
				"pcr_index": map[string]interface{}{
					"type":        "integer",
					"description": "PCR index to extend (0-23)",
				},
				"data": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded data to extend into the PCR",
				},
			},
			"required": []string{"bundle_id", "pcr_index", "data"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_bundle_seal",
		Description: "Seal data to the TPM state, optionally binding to PCR values",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bundle_id": map[string]interface{}{
					"type":        "string",
					"description": "Bundle ID of the running vTPM",
				},
				"data": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded data to seal",
				},
				"pcrs": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "integer"},
					"description": "PCR indices for sealing policy (0-23)",
				},
				"auth_value": map[string]interface{}{
					"type":        "string",
					"description": "Optional password/auth value for the sealed data",
				},
			},
			"required": []string{"bundle_id", "data"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_bundle_unseal",
		Description: "Unseal data from the TPM (requires matching PCR state)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bundle_id": map[string]interface{}{
					"type":        "string",
					"description": "Bundle ID of the running vTPM",
				},
				"sealed_data": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded sealed data to unseal",
				},
				"auth_value": map[string]interface{}{
					"type":        "string",
					"description": "Optional password/auth value if set during seal",
				},
			},
			"required": []string{"bundle_id", "sealed_data"},
		},
	})
}
