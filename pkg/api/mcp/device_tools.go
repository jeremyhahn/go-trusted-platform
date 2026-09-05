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
// Device Error Types
// =============================================================================

// DeviceError represents a device operation error.
type DeviceError struct {
	Code    string
	Message string
}

func (e *DeviceError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ErrDeviceServiceUnavailable indicates the device service is not available.
var ErrDeviceServiceUnavailable = &DeviceError{
	Code:    "DEVICE_SERVICE_UNAVAILABLE",
	Message: "device service is not available",
}

// ErrDeviceSerialRequired indicates a device serial is required.
var ErrDeviceSerialRequired = &DeviceError{
	Code:    "DEVICE_SERIAL_REQUIRED",
	Message: "device serial is required",
}

// ErrDeviceIDRequired indicates a device ID is required.
var ErrDeviceIDRequired = &DeviceError{
	Code:    "DEVICE_ID_REQUIRED",
	Message: "device ID is required",
}

// ErrDeviceNotFound indicates a device was not found.
var ErrDeviceNotFound = &DeviceError{
	Code:    "DEVICE_NOT_FOUND",
	Message: "device not found",
}

// ErrProfileNameRequired indicates a profile name is required.
var ErrProfileNameRequired = &DeviceError{
	Code:    "PROFILE_NAME_REQUIRED",
	Message: "profile name is required",
}

// ErrProfileIDRequired indicates a profile ID is required.
var ErrProfileIDRequired = &DeviceError{
	Code:    "PROFILE_ID_REQUIRED",
	Message: "profile ID is required",
}

// ErrProfileNotFound indicates a profile was not found.
var ErrProfileNotFound = &DeviceError{
	Code:    "PROFILE_NOT_FOUND",
	Message: "profile not found",
}

// =============================================================================
// Device Tool Registration
// =============================================================================

// registerDeviceToolsV2 registers extended device and profile management MCP tools.
// This replaces the basic device tools with comprehensive device and profile management.
func (r *ToolRegistry) registerDeviceToolsV2() {
	// Device CRUD operations
	r.addTool(ToolDefinition{
		Name:        "device_create",
		Description: "Register a new device in the system with its TPM credentials and attestation keys",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"serial": map[string]interface{}{
					"type":        "string",
					"description": "Device serial number (required, unique identifier)",
				},
				"model": map[string]interface{}{
					"type":        "string",
					"description": "Device model name",
				},
				"attest_pub": map[string]interface{}{
					"type":        "string",
					"description": "PEM-encoded attestation public key",
				},
				"attest_cert": map[string]interface{}{
					"type":        "string",
					"description": "PEM-encoded attestation (IAK/AK) certificate issued by the platform CA; the trust anchor for quote verification",
				},
				"signing_pub": map[string]interface{}{
					"type":        "string",
					"description": "PEM-encoded signing public key",
				},
				"ek_cert": map[string]interface{}{
					"type":        "string",
					"description": "PEM-encoded endorsement key certificate",
				},
				"event_log": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded TPM event log",
				},
				"hash_algo_id": map[string]interface{}{
					"type":        "integer",
					"description": "Hash algorithm ID for PCR calculations",
				},
			},
			"required": []string{"serial"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_get_by_id",
		Description: "Get device details by numeric ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "integer",
					"description": "Device ID",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_get_by_serial",
		Description: "Get device details by serial number",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"serial": map[string]interface{}{
					"type":        "string",
					"description": "Device serial number",
				},
			},
			"required": []string{"serial"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_list_all",
		Description: "List all devices with optional pagination",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"page": map[string]interface{}{
					"type":        "integer",
					"description": "Page number (1-based)",
					"default":     1,
				},
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Number of devices per page",
					"default":     50,
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_update_by_id",
		Description: "Update device properties by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "integer",
					"description": "Device ID",
				},
				"serial": map[string]interface{}{
					"type":        "string",
					"description": "New device serial number",
				},
				"model": map[string]interface{}{
					"type":        "string",
					"description": "New device model name",
				},
				"attest_pub": map[string]interface{}{
					"type":        "string",
					"description": "New PEM-encoded attestation public key",
				},
				"attest_cert": map[string]interface{}{
					"type":        "string",
					"description": "New PEM-encoded attestation (IAK/AK) certificate issued by the platform CA",
				},
				"signing_pub": map[string]interface{}{
					"type":        "string",
					"description": "New PEM-encoded signing public key",
				},
				"ek_cert": map[string]interface{}{
					"type":        "string",
					"description": "New PEM-encoded endorsement key certificate",
				},
				"event_log": map[string]interface{}{
					"type":        "string",
					"description": "New base64-encoded TPM event log",
				},
				"hash_algo_id": map[string]interface{}{
					"type":        "integer",
					"description": "New hash algorithm ID",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_delete_by_id",
		Description: "Delete a device by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "integer",
					"description": "Device ID",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_get_status",
		Description: "Get the current status of a device including attestation state",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "integer",
					"description": "Device ID",
				},
			},
			"required": []string{"id"},
		},
	})

	// Profile CRUD operations
	r.addTool(ToolDefinition{
		Name:        "profile_create",
		Description: "Create a new device profile with network configuration and matching rules",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Profile name (required, unique identifier)",
				},
				"model": map[string]interface{}{
					"type":        "string",
					"description": "Target device model for this profile",
				},
				"role": map[string]interface{}{
					"type":        "string",
					"description": "Device role (server, client, workstation, edge, iot, gateway, load-balancer)",
				},
				"event_log": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded reference event log for attestation",
				},
				"zone": map[string]interface{}{
					"type":        "string",
					"description": "Default SDN zone for this profile",
				},
				"networks": map[string]interface{}{
					"type": "object",
					"additionalProperties": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"vlan":        map[string]interface{}{"type": "integer", "description": "VLAN ID"},
							"static_ip":   map[string]interface{}{"type": "string", "description": "Static IP address"},
							"gateway":     map[string]interface{}{"type": "string", "description": "Default gateway"},
							"dns":         map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "DNS servers"},
							"auth_method": map[string]interface{}{"type": "string", "description": "Auth method (none, 802.1x)"},
							"zone":        map[string]interface{}{"type": "string", "description": "SDN zone for this phase"},
						},
					},
					"description": "Network phase configurations keyed by name (e.g. provisioning, trusted, quarantine)",
				},
				"enrollment_network": map[string]interface{}{
					"type":        "string",
					"description": "Key of the network used during enrollment (default: provisioning)",
				},
				"post_enrollment_network": map[string]interface{}{
					"type":        "string",
					"description": "Key of the network after enrollment success (default: trusted)",
				},
				"failure_network": map[string]interface{}{
					"type":        "string",
					"description": "Key of the network on enrollment/attestation failure (default: quarantine)",
				},
				"match_rules": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"mac_prefix":    map[string]interface{}{"type": "string", "description": "MAC address prefix to match"},
						"serial_prefix": map[string]interface{}{"type": "string", "description": "Serial number prefix to match"},
						"model":         map[string]interface{}{"type": "string", "description": "Device model to match"},
					},
					"description": "Rules for auto-assigning this profile to devices",
				},
				"ek_serial": map[string]interface{}{
					"type":        "string",
					"description": "Exact TPM EK certificate serial number for device identity resolution at boot",
				},
				"ek_cert": map[string]interface{}{
					"type":        "string",
					"description": "Prestaged PEM-encoded TPM EK certificate binding config delivery and remote UKI signing to the hardware EK (must be a valid PEM X.509 certificate)",
				},
				"mac_address": map[string]interface{}{
					"type":        "string",
					"description": "Exact MAC address for non-TPM device identification",
				},
				"config": map[string]interface{}{
					"type":        "object",
					"description": "Full merged platform config delivered to the device",
				},
				"assigned": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether the profile is bound to a specific device",
				},
				"assigned_at": map[string]interface{}{
					"type":        "string",
					"description": "RFC3339 timestamp of the device assignment",
				},
				"tls_server_name": map[string]interface{}{
					"type":        "string",
					"description": "Certificate name the attestation collector verifies a node of this profile against when it dials it for a quote (e.g. compute.trusted-platform.internal); empty means the device's own FQDN. The result also reports the read-only pcr_baseline, which no argument can set",
				},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "profile_get_by_id",
		Description: "Get profile details by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "integer",
					"description": "Profile ID",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "profile_list_all",
		Description: "List all profiles with optional pagination",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"page": map[string]interface{}{
					"type":        "integer",
					"description": "Page number (1-based)",
					"default":     1,
				},
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Number of profiles per page",
					"default":     50,
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "profile_update_by_id",
		Description: "Update profile properties by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "integer",
					"description": "Profile ID",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "New profile name",
				},
				"model": map[string]interface{}{
					"type":        "string",
					"description": "New target device model",
				},
				"role": map[string]interface{}{
					"type":        "string",
					"description": "New device role",
				},
				"event_log": map[string]interface{}{
					"type":        "string",
					"description": "New base64-encoded reference event log",
				},
				"zone": map[string]interface{}{
					"type":        "string",
					"description": "Default SDN zone for this profile",
				},
				"networks": map[string]interface{}{
					"type":        "object",
					"description": "Network phase configurations keyed by name",
				},
				"enrollment_network": map[string]interface{}{
					"type":        "string",
					"description": "Key of the enrollment network",
				},
				"post_enrollment_network": map[string]interface{}{
					"type":        "string",
					"description": "Key of the post-enrollment network",
				},
				"failure_network": map[string]interface{}{
					"type":        "string",
					"description": "Key of the failure/quarantine network",
				},
				"match_rules": map[string]interface{}{
					"type":        "object",
					"description": "New match rules configuration",
				},
				"ek_serial": map[string]interface{}{
					"type":        "string",
					"description": "New exact TPM EK certificate serial number",
				},
				"ek_cert": map[string]interface{}{
					"type":        "string",
					"description": "New prestaged PEM-encoded TPM EK certificate (must be a valid PEM X.509 certificate)",
				},
				"mac_address": map[string]interface{}{
					"type":        "string",
					"description": "New exact MAC address",
				},
				"config": map[string]interface{}{
					"type":        "object",
					"description": "New full merged platform config",
				},
				"assigned": map[string]interface{}{
					"type":        "boolean",
					"description": "New assignment flag",
				},
				"assigned_at": map[string]interface{}{
					"type":        "string",
					"description": "New RFC3339 assignment timestamp",
				},
				"tls_server_name": map[string]interface{}{
					"type":        "string",
					"description": "New certificate name the attestation collector verifies a node of this profile against; omitted, the stored name is kept. pcr_baseline is read-only and ignored if supplied",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "profile_delete_by_id",
		Description: "Delete a profile by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "integer",
					"description": "Profile ID",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "profile_assign_to_device",
		Description: "Bind a profile to a specific device identity (TPM EK certificate serial and/or MAC address), optionally prestaging the device's PEM-encoded EK certificate. The EK certificate is source-agnostic: it may come from a swtpm-backed vTPM or a physical hardware TPM. At least one of ek_serial or mac_address is required.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"profile_id": map[string]interface{}{
					"type":        "integer",
					"description": "Profile ID to assign",
				},
				"ek_serial": map[string]interface{}{
					"type":        "string",
					"description": "TPM EK certificate serial number identifying the device",
				},
				"mac_address": map[string]interface{}{
					"type":        "string",
					"description": "Exact MAC address identifying the device (for non-TPM identification)",
				},
				"ek_cert": map[string]interface{}{
					"type":        "string",
					"description": "Optional prestaged PEM-encoded TPM EK certificate binding config delivery and remote UKI signing to the hardware EK (must be a valid PEM X.509 certificate; empty leaves any existing prestaged certificate untouched)",
				},
			},
			"required": []string{"profile_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "profile_unassign_from_device",
		Description: "Clear a profile's device binding: the EK serial, MAC address, prestaged EK certificate, and assignment state are all reset",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"profile_id": map[string]interface{}{
					"type":        "integer",
					"description": "Profile ID to unassign",
				},
			},
			"required": []string{"profile_id"},
		},
	})
}
