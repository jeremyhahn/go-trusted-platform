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

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *DeviceError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
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

// ErrDeviceHashAlgoInvalid indicates a hash_algo_id outside the uint32 range
// of a TPM algorithm identifier.
var ErrDeviceHashAlgoInvalid = &DeviceError{
	Code:    "DEVICE_HASH_ALGO_INVALID",
	Message: "hash_algo_id must be a TPM algorithm identifier between 0 and 4294967295",
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

// registerDeviceToolsV2 registers the device profile management MCP tools.
// Device records are served by the device_* family in registerDeviceTools;
// every tool registered here routes through deviceProfileToolDispatch.
func (r *ToolRegistry) registerDeviceToolsV2() {
	// Profile CRUD operations
	r.addTool(mcpwire.ToolDefinition{
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
				"dice_device_id": map[string]interface{}{
					"type":        "string",
					"description": "Hex DICE device identifier (1 to 64 bytes) the registry resolves a DICE-attested node to",
				},
				"golden_fw_hash": map[string]interface{}{
					"type":        "string",
					"description": "Hex expected firmware measurement (FWHash, 32 bytes) of the device bound to this profile",
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
					"description": "Certificate name the attestation collector verifies a node of this profile against when it dials it for a quote (e.g. compute.example.internal); empty means the device's own FQDN. The result also reports the read-only pcr_baseline, which no argument can set",
				},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
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

	r.addTool(mcpwire.ToolDefinition{
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

	r.addTool(mcpwire.ToolDefinition{
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
				"dice_device_id": map[string]interface{}{
					"type":        "string",
					"description": "New hex DICE device identifier (1 to 64 bytes); omitted or empty keeps the stored one",
				},
				"golden_fw_hash": map[string]interface{}{
					"type":        "string",
					"description": "New hex golden firmware hash (FWHash, 32 bytes); omitted or empty keeps the stored one",
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
					"description": "New certificate name the attestation collector verifies a node of this profile against; omitted, the stored name is kept; an empty string clears it, so the collector verifies against each device's own FQDN again. pcr_baseline is read-only and ignored if supplied",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
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

	r.addTool(mcpwire.ToolDefinition{
		Name:        "profile_find_matching",
		Description: "Find profile matching device attributes",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"mac_address": map[string]interface{}{
					"type":        "string",
					"description": "Device MAC address",
				},
				"serial": map[string]interface{}{
					"type":        "string",
					"description": "Device serial number",
				},
				"model": map[string]interface{}{
					"type":        "string",
					"description": "Device model",
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "profile_find_by_mac",
		Description: "Find the profile whose MAC prefix rule fits a device MAC address",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"mac_address": map[string]interface{}{
					"type":        "string",
					"description": "Device MAC address",
				},
			},
			"required": []string{"mac_address"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "profile_find_by_serial",
		Description: "Find the profile whose serial prefix rule fits a device serial number",
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

	r.addTool(mcpwire.ToolDefinition{
		Name:        "profile_find_config",
		Description: "Find the profile a booting device receives, by EK serial first and MAC address second",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ek_serial": map[string]interface{}{
					"type":        "string",
					"description": "Device EK certificate serial",
				},
				"mac_address": map[string]interface{}{
					"type":        "string",
					"description": "Device MAC address",
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "profile_assign_to_device",
		Description: "Bind a profile to a specific device identity: an already-registered device (device_id; the server derives the EK serial from its stored EK certificate and prestages it), or an explicit TPM EK certificate serial and/or MAC address, optionally prestaging the device's PEM-encoded EK certificate. The EK certificate is source-agnostic: it may come from a swtpm-backed vTPM or a physical hardware TPM. At least one of device_id, ek_serial or mac_address is required; explicit values override what device_id derives.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"profile_id": map[string]interface{}{
					"type":        "integer",
					"description": "Profile ID to assign",
				},
				"device_id": map[string]interface{}{
					"type":        "integer",
					"description": "Registered device ID to bind to; its stored EK certificate supplies the EK serial and the prestaged certificate",
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

	r.addTool(mcpwire.ToolDefinition{
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

	r.registerDeviceTemplateTools()
}
