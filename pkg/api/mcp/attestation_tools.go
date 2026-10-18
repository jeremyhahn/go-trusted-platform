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
// Attestation Error Types
// =============================================================================

// AttestationError represents an attestation operation error.
type AttestationError struct {
	Code    string
	Message string
}

func (e *AttestationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *AttestationError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
}

// ErrAttestationServiceUnavailable indicates the attestation service is not available.
var ErrAttestationServiceUnavailable = &AttestationError{
	Code:    "ATTESTATION_SERVICE_UNAVAILABLE",
	Message: "attestation service is not available",
}

// ErrManifestIDRequired indicates a manifest ID is required.
var ErrManifestIDRequired = &AttestationError{
	Code:    "MANIFEST_ID_REQUIRED",
	Message: "manifest ID is required",
}

// =============================================================================
// Attestation Tool Registration
// =============================================================================

// registerAttestationTools registers attestation-related MCP tools.
func (r *ToolRegistry) registerAttestationTools() {
	// Manifest operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_create_manifest",
		Description: "Create a new attestation manifest for a host and its workloads",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"host_id": map[string]interface{}{
					"type":        "string",
					"description": "Host identifier for the manifest",
				},
				"nonce": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded nonce for freshness (min 16 bytes)",
				},
				"pcr_indices": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "integer"},
					"description": "PCR indices to include (default: 0-7, 14)",
				},
				"hash_algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Hash algorithm (sha256, sha384, sha512)",
					"default":     "sha256",
				},
				"include_vms": map[string]interface{}{
					"type":        "boolean",
					"description": "Include VM attestations in manifest",
					"default":     false,
				},
				"include_containers": map[string]interface{}{
					"type":        "boolean",
					"description": "Include container attestations in manifest",
					"default":     false,
				},
				"vm_ids": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Specific VM IDs to include (empty = all)",
				},
				"container_ids": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Specific container IDs to include (empty = all)",
				},
				"sign": map[string]interface{}{
					"type":        "boolean",
					"description": "Sign the manifest with platform key",
					"default":     true,
				},
			},
			"required": []string{"host_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_get_manifest",
		Description: "Get an attestation manifest by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Manifest ID to retrieve",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_list_manifests",
		Description: "List attestation manifests with pagination",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of manifests to return",
					"default":     50,
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"description": "Number of manifests to skip for pagination",
					"default":     0,
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_delete_manifest",
		Description: "Delete an attestation manifest by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Manifest ID to delete",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_verify_manifest",
		Description: "Verify a stored attestation manifest's nonce, PCR values and freshness",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Manifest ID to verify",
				},
				"expected_nonce": map[string]interface{}{
					"type":        "string",
					"description": "Expected nonce value (base64-encoded)",
				},
				"public_key_pem": map[string]interface{}{
					"type":        "string",
					"description": "PEM-encoded public key; refused (FailedPrecondition): the service cannot check a manifest signature against it",
				},
				"expected_pcrs": map[string]interface{}{
					"type":        "object",
					"description": "Expected PCR values as map of index to base64 value",
				},
			},
			"required": []string{"id"},
		},
	})
}
