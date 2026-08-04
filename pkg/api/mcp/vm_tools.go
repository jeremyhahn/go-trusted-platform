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

// registerVMTools registers VM-related MCP tools.
func (r *ToolRegistry) registerVMTools() {
	r.addTool(ToolDefinition{
		Name:        "vm_create",
		Description: "Create a new virtual machine with the specified configuration",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "VM name (required, must start with a letter, alphanumeric with hyphens/underscores)",
				},
				"profile_id": map[string]interface{}{
					"type":        "integer",
					"description": "Device profile ID to use for VM configuration",
				},
				"profile_name": map[string]interface{}{
					"type":        "string",
					"description": "Device profile name to use for VM configuration",
				},
				"memory": map[string]interface{}{
					"type":        "integer",
					"description": "Memory in MB (e.g., 2048 for 2GB)",
					"default":     2048,
				},
				"cpus": map[string]interface{}{
					"type":        "integer",
					"description": "Number of CPU cores",
					"default":     2,
				},
				"disk_size": map[string]interface{}{
					"type":        "string",
					"description": "Disk size (e.g., '20G', '100G')",
					"default":     "20G",
				},
				"iso_path": map[string]interface{}{
					"type":        "string",
					"description": "Path to installation ISO (for install mode)",
				},
				"boot_mode": map[string]interface{}{
					"type":        "string",
					"description": "Boot mode (install, boot, pxe)",
					"default":     "boot",
				},
				"enable_kvm": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable KVM hardware acceleration",
					"default":     true,
				},
				"secure_boot": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable UEFI Secure Boot",
					"default":     false,
				},
				"tpm_enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable virtual TPM for the VM",
					"default":     true,
				},
				"network_mode": map[string]interface{}{
					"type":        "string",
					"description": "Network mode (bridge, nat, none)",
					"default":     "bridge",
				},
				"environment": map[string]interface{}{
					"type":        "object",
					"description": "Environment variables as key-value pairs",
				},
				"labels": map[string]interface{}{
					"type":        "object",
					"description": "VM labels as key-value pairs",
				},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
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

	r.addTool(ToolDefinition{
		Name:        "vm_list",
		Description: "List virtual machines with optional filters",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"state": map[string]interface{}{
					"type":        "string",
					"description": "Filter by state (running, stopped, creating, etc.)",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Filter by name (substring match)",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of VMs to return",
					"default":     50,
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vm_update",
		Description: "Update virtual machine configuration",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "VM ID or name",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "New VM name",
				},
				"memory": map[string]interface{}{
					"type":        "integer",
					"description": "Memory in MB",
				},
				"cpus": map[string]interface{}{
					"type":        "integer",
					"description": "Number of CPU cores",
				},
				"environment": map[string]interface{}{
					"type":        "object",
					"description": "Environment variables to set or update",
				},
				"labels": map[string]interface{}{
					"type":        "object",
					"description": "Labels to set or update",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(ToolDefinition{
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

	r.addTool(ToolDefinition{
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

	r.addTool(ToolDefinition{
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

	r.addTool(ToolDefinition{
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

	r.addTool(ToolDefinition{
		Name:        "vm_suspend",
		Description: "Suspend a running virtual machine",
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

	r.addTool(ToolDefinition{
		Name:        "vm_resume",
		Description: "Resume a suspended virtual machine",
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

	r.addTool(ToolDefinition{
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

	r.addTool(ToolDefinition{
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

	r.addTool(ToolDefinition{
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

	r.addTool(ToolDefinition{
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

	r.addTool(ToolDefinition{
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

	r.addTool(ToolDefinition{
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

	r.addTool(ToolDefinition{
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
