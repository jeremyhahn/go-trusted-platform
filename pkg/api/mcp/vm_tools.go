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

// registerVMTools registers VM-related MCP tools.
func (r *ToolRegistry) registerVMTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_create",
		Description: "Create a virtual machine, as ComputeService.CreateVM does",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "VM name (required)",
				},
				"memory": map[string]interface{}{
					"type":        "integer",
					"description": "Memory in MB; omitted, ComputeService's default applies",
				},
				"cpus": map[string]interface{}{
					"type":        "integer",
					"description": "Number of CPU cores; omitted, ComputeService's default applies",
				},
				"secure_boot": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable UEFI Secure Boot",
					"default":     false,
				},
				"tpm_enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable a virtual TPM for the VM",
					"default":     false,
				},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_get",
		Description: "Get detailed information about a virtual machine by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_list",
		Description: "List every virtual machine, as ComputeService.ListVMs does",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_delete",
		Description: "Delete a virtual machine",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_start",
		Description: "Start a stopped virtual machine",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_stop",
		Description: "Stop a running virtual machine",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_reboot",
		Description: "Reboot a virtual machine",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_snapshot_create",
		Description: "Create a snapshot of a virtual machine",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Snapshot name",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "Snapshot description",
				},
			},
			"required": []string{"vm_id", "name"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_snapshot_get",
		Description: "Get details of a specific VM snapshot",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
				"snapshot_id": map[string]interface{}{
					"type":        "string",
					"description": "Snapshot ID or name",
				},
			},
			"required": []string{"vm_id", "snapshot_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_snapshot_list",
		Description: "List all snapshots for a virtual machine",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
			},
			"required": []string{"vm_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_snapshot_delete",
		Description: "Delete a VM snapshot",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
				"snapshot_id": map[string]interface{}{
					"type":        "string",
					"description": "Snapshot ID or name",
				},
			},
			"required": []string{"vm_id", "snapshot_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_snapshot_restore",
		Description: "Restore a virtual machine from a snapshot",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
				"snapshot_id": map[string]interface{}{
					"type":        "string",
					"description": "Snapshot ID or name to restore from",
				},
			},
			"required": []string{"vm_id", "snapshot_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_attest",
		Description: "Perform TPM attestation for a virtual machine, generating a cryptographic proof of its integrity",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
				"nonce": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded nonce for freshness (optional)",
				},
				"include_pcrs": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "integer"},
					"description": "PCR indices to include in attestation (optional)",
				},
				"include_event_log": map[string]interface{}{
					"type":        "boolean",
					"description": "Include event log in response",
					"default":     false,
				},
			},
			"required": []string{"vm_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_attest_verify",
		Description: "Verify VM attestation evidence (quote, signature, nonce, expected PCR values) against the VM's live vTPM attestation key",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
				"quote": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded TPMS_ATTEST quote structure",
				},
				"signature": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded AK signature over the quote",
				},
				"signature_algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Scheme the quote declares, as vm_attest returned it (e.g. SHA256-RSAPSS); an absent or unknown scheme fails verification",
				},
				"nonce": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded expected anti-replay nonce",
				},
				"expected_pcrs": map[string]interface{}{
					"type":        "object",
					"description": "Expected PCR values as a map of PCR index to base64-encoded SHA-256 value; the index set must match the quote's PCR selection",
				},
			},
			"required": []string{"vm_id", "quote", "signature", "nonce"},
		},
	})
}

// =============================================================================
// VM Error Types
// =============================================================================

// VMError represents a VM operation error.
type VMError struct {
	Code    string
	Message string
}

func (e *VMError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *VMError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
}

// ErrVMServiceUnavailable indicates the VM service is not available.
var ErrVMServiceUnavailable = &VMError{
	Code:    "VM_SERVICE_UNAVAILABLE",
	Message: "VM service is not available",
}

// ErrVMNameRequired indicates a VM name is required.
var ErrVMNameRequired = &VMError{
	Code:    "VM_NAME_REQUIRED",
	Message: "VM name is required",
}

// ErrVMIDRequired indicates a VM ID is required.
var ErrVMIDRequired = &VMError{
	Code:    "VM_ID_REQUIRED",
	Message: "VM ID is required",
}

// ErrVMNotFound indicates a VM was not found.
var ErrVMNotFound = &VMError{
	Code:    "VM_NOT_FOUND",
	Message: "VM not found",
}

// ErrSnapshotNameRequired indicates a snapshot name is required.
var ErrSnapshotNameRequired = &VMError{
	Code:    "SNAPSHOT_NAME_REQUIRED",
	Message: "snapshot name is required",
}

// ErrSnapshotIDRequired indicates a snapshot ID is required.
var ErrSnapshotIDRequired = &VMError{
	Code:    "SNAPSHOT_ID_REQUIRED",
	Message: "snapshot ID is required",
}

// ErrSnapshotNotFound indicates a snapshot was not found.
var ErrSnapshotNotFound = &VMError{
	Code:    "SNAPSHOT_NOT_FOUND",
	Message: "snapshot not found",
}

// ErrVMOperationFailedError indicates a VM operation failed.
type ErrVMOperationFailedError struct {
	Operation string
	Cause     error
}

func (e *ErrVMOperationFailedError) Error() string {
	return fmt.Sprintf("VM operation %s failed: %v", e.Operation, e.Cause)
}

func (e *ErrVMOperationFailedError) Unwrap() error {
	return e.Cause
}
