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

// ErrReportIDRequired indicates a report ID is required.
var ErrReportIDRequired = &AttestationError{
	Code:    "REPORT_ID_REQUIRED",
	Message: "report ID is required",
}

// ErrPolicyIDRequired indicates a policy ID is required.
var ErrPolicyIDRequired = &AttestationError{
	Code:    "POLICY_ID_REQUIRED",
	Message: "policy ID is required",
}

// ErrPolicyNameRequired indicates a policy name is required.
var ErrPolicyNameRequired = &AttestationError{
	Code:    "POLICY_NAME_REQUIRED",
	Message: "policy name is required",
}

// ErrHostIDRequired indicates a host ID is required.
var ErrHostIDRequired = &AttestationError{
	Code:    "HOST_ID_REQUIRED",
	Message: "host ID is required",
}

// ErrWorkloadIDRequired indicates a workload ID is required.
var ErrWorkloadIDRequired = &AttestationError{
	Code:    "WORKLOAD_ID_REQUIRED",
	Message: "workload ID is required",
}

// ErrWorkloadTypeRequired indicates a workload type is required.
var ErrWorkloadTypeRequired = &AttestationError{
	Code:    "WORKLOAD_TYPE_REQUIRED",
	Message: "workload type is required",
}

// ErrEvidenceRequired indicates attestation evidence is required.
var ErrEvidenceRequired = &AttestationError{
	Code:    "EVIDENCE_REQUIRED",
	Message: "attestation evidence is required",
}

// ErrAttestationDataRequired indicates attestation data is required.
var ErrAttestationDataRequired = &AttestationError{
	Code:    "ATTESTATION_DATA_REQUIRED",
	Message: "attestation data is required",
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
		Description: "Verify an attestation manifest including signature and Merkle root",
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
					"description": "PEM-encoded public key for signature verification",
				},
				"expected_pcrs": map[string]interface{}{
					"type":        "object",
					"description": "Expected PCR values as map of index to base64 value",
				},
			},
			"required": []string{"id"},
		},
	})

	// Report operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_create_report",
		Description: "Generate an attestation report for a host or workload",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"host_id": map[string]interface{}{
					"type":        "string",
					"description": "Host identifier",
				},
				"manifest_id": map[string]interface{}{
					"type":        "string",
					"description": "Associated manifest ID",
				},
				"policy_id": map[string]interface{}{
					"type":        "string",
					"description": "Policy ID to evaluate against",
				},
				"workload_id": map[string]interface{}{
					"type":        "string",
					"description": "Workload identifier (container/VM)",
				},
				"workload_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of workload (container, vm, device)",
				},
				"hash_algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Hash algorithm (sha256, sha384, sha512)",
					"default":     "sha256",
				},
			},
			"required": []string{"host_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_get_report",
		Description: "Get an attestation report by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Report ID to retrieve",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_list_reports",
		Description: "List attestation reports with optional filtering",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"host_id": map[string]interface{}{
					"type":        "string",
					"description": "Filter by host ID",
				},
				"status": map[string]interface{}{
					"type":        "string",
					"description": "Filter by status (valid, invalid, expired)",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of reports to return",
					"default":     50,
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"description": "Number of reports to skip for pagination",
					"default":     0,
				},
			},
		},
	})

	// Policy operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_create_policy",
		Description: "Create a new attestation policy with PCR requirements and golden values",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Policy name (unique identifier)",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "Policy description",
				},
				"pcr_policy": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"required_pcrs": map[string]interface{}{
							"type":        "array",
							"items":       map[string]interface{}{"type": "integer"},
							"description": "PCR indices that must be present",
						},
						"allowed_hash_algorithms": map[string]interface{}{
							"type":        "array",
							"items":       map[string]interface{}{"type": "string"},
							"description": "Allowed hash algorithms",
						},
						"expected_values": map[string]interface{}{
							"type":        "object",
							"description": "Expected PCR values as map of index to base64 value",
						},
						"allow_zero_values": map[string]interface{}{
							"type":        "boolean",
							"description": "Allow all-zero PCR values",
							"default":     false,
						},
					},
					"description": "PCR-specific policy requirements",
				},
				"golden_values": map[string]interface{}{
					"type":        "object",
					"description": "Golden/expected PCR values as map of index to base64 value",
				},
				"max_age": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum age of attestation in seconds",
				},
				"active": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether the policy is active",
					"default":     true,
				},
				"metadata": map[string]interface{}{
					"type":        "object",
					"description": "Additional metadata as key-value pairs",
				},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_get_policy",
		Description: "Get an attestation policy by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Policy ID to retrieve",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_list_policies",
		Description: "List attestation policies with optional filtering",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Filter by policy name (partial match)",
				},
				"active": map[string]interface{}{
					"type":        "boolean",
					"description": "Filter by active status",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of policies to return",
					"default":     50,
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"description": "Number of policies to skip for pagination",
					"default":     0,
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_delete_policy",
		Description: "Delete an attestation policy by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Policy ID to delete",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_evaluate_policy",
		Description: "Evaluate attestation evidence against a policy",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"policy_id": map[string]interface{}{
					"type":        "string",
					"description": "Policy ID to evaluate against",
				},
				"evidence": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"pcr_values": map[string]interface{}{
							"type":        "object",
							"description": "PCR values as map of index to base64 value",
						},
						"quote": map[string]interface{}{
							"type":        "string",
							"description": "Base64-encoded TPM quote",
						},
						"signature": map[string]interface{}{
							"type":        "string",
							"description": "Base64-encoded signature",
						},
						"timestamp": map[string]interface{}{
							"type":        "string",
							"description": "Evidence timestamp in RFC3339 format",
						},
						"hash_algorithm": map[string]interface{}{
							"type":        "string",
							"description": "Hash algorithm used",
						},
						"metadata": map[string]interface{}{
							"type":        "object",
							"description": "Additional evidence metadata",
						},
					},
					"required":    []string{"pcr_values"},
					"description": "Attestation evidence to evaluate",
				},
			},
			"required": []string{"policy_id", "evidence"},
		},
	})

	// Workload attestation operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_attest_workload",
		Description: "Perform attestation for a workload (container, VM, or device)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"workload_id": map[string]interface{}{
					"type":        "string",
					"description": "Workload identifier",
				},
				"workload_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of workload (container, vm, device)",
				},
				"nonce": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded nonce for freshness",
				},
				"pcr_indices": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "integer"},
					"description": "PCR indices to include",
				},
				"hash_algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Hash algorithm (sha256, sha384, sha512)",
					"default":     "sha256",
				},
				"include_event_log": map[string]interface{}{
					"type":        "boolean",
					"description": "Include TPM event log in result",
					"default":     false,
				},
				"policy_id": map[string]interface{}{
					"type":        "string",
					"description": "Policy ID to evaluate against",
				},
			},
			"required": []string{"workload_id", "workload_type"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "attestation_verify_workload",
		Description: "Verify previously collected workload attestation data",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"workload_id": map[string]interface{}{
					"type":        "string",
					"description": "Workload identifier",
				},
				"workload_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of workload (container, vm, device)",
				},
				"attestation_data": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded attestation data to verify",
				},
			},
			"required": []string{"workload_id", "workload_type", "attestation_data"},
		},
	})
}
