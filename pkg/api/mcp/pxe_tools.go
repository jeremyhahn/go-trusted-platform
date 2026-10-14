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
	"context"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"google.golang.org/grpc/status"
)

// =============================================================================
// PXE Error Types
// =============================================================================

// PXEError represents a PXE operation error.
type PXEError struct {
	Code    string
	Message string
}

func (e *PXEError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *PXEError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
}

// ErrPXEServiceUnavailable indicates the PXE service is not available.
var ErrPXEServiceUnavailable = &PXEError{
	Code:    "PXE_SERVICE_UNAVAILABLE",
	Message: "PXE provisioning service is not available",
}

// ErrPXEDeviceIDRequired indicates a device ID is required.
var ErrPXEDeviceIDRequired = &PXEError{
	Code:    "PXE_DEVICE_ID_REQUIRED",
	Message: "device ID is required",
}

// ErrPXEMACAddressRequired indicates a MAC address is required.
var ErrPXEMACAddressRequired = &PXEError{
	Code:    "PXE_MAC_ADDRESS_REQUIRED",
	Message: "MAC address is required",
}

// ErrPXEPortIDRequired indicates a port ID is required.
var ErrPXEPortIDRequired = &PXEError{
	Code:    "PXE_PORT_ID_REQUIRED",
	Message: "port ID is required",
}

// ErrPXEStateRequired indicates a state is required.
var ErrPXEStateRequired = &PXEError{
	Code:    "PXE_STATE_REQUIRED",
	Message: "state is required",
}

// ErrPXEDeviceNotFound indicates a device was not found.
var ErrPXEDeviceNotFound = &PXEError{
	Code:    "PXE_DEVICE_NOT_FOUND",
	Message: "device not found",
}

// ErrPXEInvalidState indicates an invalid provisioning state.
var ErrPXEInvalidState = &PXEError{
	Code:    "PXE_INVALID_STATE",
	Message: "invalid provisioning state",
}

// =============================================================================
// PXE Tool Handler
// =============================================================================

// =============================================================================
// PXE Tool Registration
// =============================================================================

// registerPXETools registers all PXE provisioning MCP tools.
func (r *ToolRegistry) registerPXETools() {
	// pxe_list_devices - List all provisioning devices
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_list_devices",
		Description: "List all devices in the PXE provisioning workflow with optional filtering by state, MAC address, or VLAN",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"state": map[string]interface{}{
					"type":        "string",
					"description": "Filter by provisioning state (discovered, booting, installing, install_complete, enrolling, enrolled, authorizing, authorized, failed, quarantined)",
				},
				"mac_address": map[string]interface{}{
					"type":        "string",
					"description": "Filter by MAC address (exact match or prefix)",
				},
				"vlan": map[string]interface{}{
					"type":        "integer",
					"description": "Filter by current VLAN assignment",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of results to return",
					"default":     50,
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"description": "Number of results to skip for pagination",
					"default":     0,
				},
			},
		},
	})

	// pxe_get_device - Get a specific device by device ID
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_get_device",
		Description: "Get detailed information about a specific device by its device ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{
					"type":        "string",
					"description": "Device ID (unique identifier based on MAC hash)",
				},
			},
			"required": []string{"device_id"},
		},
	})

	// pxe_get_device_by_mac - Get a specific device by MAC address
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_get_device_by_mac",
		Description: "Get detailed information about a specific device by its MAC address",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"mac_address": map[string]interface{}{
					"type":        "string",
					"description": "MAC address of the device (e.g., 00:11:22:33:44:55)",
				},
			},
			"required": []string{"mac_address"},
		},
	})

	// pxe_register_device - Register a new device for provisioning
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_register_device",
		Description: "Register a new device for PXE provisioning. The device will be assigned to the quarantine VLAN initially.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"mac_address": map[string]interface{}{
					"type":        "string",
					"description": "MAC address of the device to register (required)",
				},
				"port_id": map[string]interface{}{
					"type":        "string",
					"description": "OVS port identifier for this device (required)",
				},
			},
			"required": []string{"mac_address", "port_id"},
		},
	})

	// pxe_update_state - Update device provisioning state
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_update_state",
		Description: "Update the provisioning state of a device. State transitions must follow the allowed workflow transitions.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{
					"type":        "string",
					"description": "Device ID (required)",
				},
				"state": map[string]interface{}{
					"type":        "string",
					"description": "New provisioning state (discovered, booting, installing, install_complete, enrolling, enrolled, authorizing, authorized, failed, quarantined)",
				},
				"reason": map[string]interface{}{
					"type":        "string",
					"description": "Reason for the state change",
				},
			},
			"required": []string{"device_id", "state"},
		},
	})

	// pxe_authorize_device - Authorize device onto its target zone
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_authorize_device",
		Description: "Authorize a device onto its target network zone. Moves the device from the provisioning zone to the requested zone (e.g. trusted).",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{
					"type":        "string",
					"description": "Device ID (required)",
				},
				"target_zone": map[string]interface{}{
					"type":        "string",
					"description": "Target trust zone name (e.g. 'trusted', 'tenant')",
				},
			},
			"required": []string{"device_id", "target_zone"},
		},
	})

	// pxe_quarantine_device - Move device to quarantine
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_quarantine_device",
		Description: "Move a device to quarantine state. This restricts network access and moves the device to the quarantine VLAN.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{
					"type":        "string",
					"description": "Device ID (required)",
				},
				"reason": map[string]interface{}{
					"type":        "string",
					"description": "Reason for quarantining the device",
				},
			},
			"required": []string{"device_id", "reason"},
		},
	})

	// pxe_retry_device - Retry failed provisioning
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_retry_device",
		Description: "Retry provisioning for a device that has failed or been quarantined. Resets the device to discovered state.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{
					"type":        "string",
					"description": "Device ID (required)",
				},
			},
			"required": []string{"device_id"},
		},
	})

	// pxe_service_status - Get PXE service status
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_service_status",
		Description: "Get the current status of the PXE provisioning service including running state, device count, and configuration.",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// pxe_start_service - Start the PXE service
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_start_service",
		Description: "Start the PXE provisioning service. The service must be initialized before it can be started.",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// pxe_stop_service - Stop the PXE service
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_stop_service",
		Description: "Stop the PXE provisioning service. All active provisioning will be paused until the service is restarted.",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// pxe_get_device_events - Get device provisioning events
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_get_device_events",
		Description: "Get the audit trail of provisioning events for a specific device",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{
					"type":        "string",
					"description": "Device ID (required)",
				},
			},
			"required": []string{"device_id"},
		},
	})

	// pxe_remove_device - Remove a device from provisioning
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_remove_device",
		Description: "Remove a device from the PXE provisioning service",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{
					"type":        "string",
					"description": "Device ID (required)",
				},
			},
			"required": []string{"device_id"},
		},
	})

	// pxe_set_device_enrolled - Mark device as enrolled with certificate
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_set_device_enrolled",
		Description: "Mark a device as enrolled with PKI, recording the certificate serial number",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{
					"type":        "string",
					"description": "Device ID (required)",
				},
				"certificate_serial": map[string]interface{}{
					"type":        "string",
					"description": "Certificate serial number from enrollment (required)",
				},
			},
			"required": []string{"device_id", "certificate_serial"},
		},
	})

	// pxe_webhook_complete - Handle OS installation completion webhook
	r.addTool(mcpwire.ToolDefinition{
		Name:        "pxe_webhook_complete",
		Description: "Handle the OS installation completion webhook callback. Called by the provisioned device when installation is complete.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"mac_address": map[string]interface{}{
					"type":        "string",
					"description": "MAC address of the device that completed installation (required)",
				},
				"hostname": map[string]interface{}{
					"type":        "string",
					"description": "Hostname of the device after installation",
				},
				"success": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether the installation completed successfully (required)",
				},
				"message": map[string]interface{}{
					"type":        "string",
					"description": "Additional message or error details",
				},
			},
			"required": []string{"mac_address", "success"},
		},
	})
}

// =============================================================================
// PXE Tool Execution Handlers
// =============================================================================

// executePXEListDevices handles the pxe_list_devices tool execution.
func (r *ToolRegistry) executePXEListDevices(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	filter := &pxe.DeviceFilter{
		Limit:  getInt(args, "limit"),
		Offset: getInt(args, "offset"),
	}

	if state := getString(args, "state"); state != "" {
		filter.State = pxe.ProvisioningState(state)
	}
	if mac := getString(args, "mac_address"); mac != "" {
		filter.MACAddress = mac
	}
	if vlan := getInt(args, "vlan"); vlan > 0 {
		filter.VLAN = uint16(vlan)
	}

	devices, err := pxeSvc.ListDevices(ctx, filter)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"devices": formatDeviceList(devices),
		"count":   len(devices),
	}, nil
}

// executePXEGetDevice handles the pxe_get_device tool execution.
func (r *ToolRegistry) executePXEGetDevice(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	deviceID := getString(args, "device_id")
	if deviceID == "" {
		return nil, ErrPXEDeviceIDRequired
	}

	device, err := pxeSvc.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	return formatDeviceInfo(device), nil
}

// executePXEGetDeviceByMAC handles the pxe_get_device_by_mac tool execution.
func (r *ToolRegistry) executePXEGetDeviceByMAC(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	macAddress := getString(args, "mac_address")
	if macAddress == "" {
		return nil, ErrPXEMACAddressRequired
	}

	device, err := pxeSvc.GetDeviceByMAC(ctx, macAddress)
	if err != nil {
		return nil, err
	}

	return formatDeviceInfo(device), nil
}

// executePXERegisterDevice handles the pxe_register_device tool execution.
func (r *ToolRegistry) executePXERegisterDevice(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	macAddress := getString(args, "mac_address")
	if macAddress == "" {
		return nil, ErrPXEMACAddressRequired
	}

	portID := getString(args, "port_id")
	if portID == "" {
		return nil, ErrPXEPortIDRequired
	}

	device, err := pxeSvc.RegisterDevice(ctx, macAddress, portID)
	if err != nil {
		return nil, err
	}

	return formatDeviceInfo(device), nil
}

// executePXEUpdateState handles the pxe_update_state tool execution.
func (r *ToolRegistry) executePXEUpdateState(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	deviceID := getString(args, "device_id")
	if deviceID == "" {
		return nil, ErrPXEDeviceIDRequired
	}

	stateStr := getString(args, "state")
	if stateStr == "" {
		return nil, ErrPXEStateRequired
	}

	state := pxe.ProvisioningState(stateStr)
	if !state.IsValid() {
		return nil, ErrPXEInvalidState
	}

	reason := getString(args, "reason")
	if reason == "" {
		reason = "state updated via MCP"
	}

	err := pxeSvc.UpdateDeviceState(ctx, deviceID, state, reason)
	if err != nil {
		return nil, err
	}

	device, err := pxeSvc.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	return formatDeviceInfo(device), nil
}

// executePXEAuthorizeDevice handles the pxe_authorize_device tool execution.
// The target_zone string is resolved to a VLAN ID via GatewayNetworkZoneVLAN.
func (r *ToolRegistry) executePXEAuthorizeDevice(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	deviceID := getString(args, "device_id")
	if deviceID == "" {
		return nil, ErrPXEDeviceIDRequired
	}

	targetZone := getString(args, "target_zone")
	if targetZone == "" {
		return nil, &PXEError{
			Code:    "PXE_TARGET_ZONE_REQUIRED",
			Message: "target_zone is required",
		}
	}

	targetVLAN, err := r.service.GatewayNetworkZoneVLAN(ctx, targetZone)
	if err != nil {
		return nil, &PXEError{
			Code:    "PXE_ZONE_RESOLUTION_FAILED",
			Message: "failed to resolve zone to VLAN: " + err.Error(),
		}
	}

	if err := pxeSvc.AuthorizeDevice(ctx, deviceID, targetVLAN); err != nil {
		return nil, err
	}

	device, err := pxeSvc.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	return formatDeviceInfo(device), nil
}

// executePXEQuarantineDevice handles the pxe_quarantine_device tool execution.
func (r *ToolRegistry) executePXEQuarantineDevice(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	deviceID := getString(args, "device_id")
	if deviceID == "" {
		return nil, ErrPXEDeviceIDRequired
	}

	reason := getString(args, "reason")
	if reason == "" {
		reason = "quarantined via MCP"
	}

	err := pxeSvc.QuarantineDevice(ctx, deviceID, reason)
	if err != nil {
		return nil, err
	}

	device, err := pxeSvc.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	return formatDeviceInfo(device), nil
}

// executePXERetryDevice handles the pxe_retry_device tool execution.
func (r *ToolRegistry) executePXERetryDevice(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	deviceID := getString(args, "device_id")
	if deviceID == "" {
		return nil, ErrPXEDeviceIDRequired
	}

	err := pxeSvc.RetryDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	device, err := pxeSvc.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	return formatDeviceInfo(device), nil
}

// executePXEServiceStatus handles the pxe_service_status tool execution.
func (r *ToolRegistry) executePXEServiceStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	status := pxeSvc.Status()

	return map[string]interface{}{
		"running":           status.Running,
		"device_count":      status.DeviceCount,
		"start_time":        status.StartTime.Format("2006-01-02T15:04:05Z07:00"),
		"ipxe_server_addr":  status.IPXEServerAddr,
		"quarantine_vlan":   status.QuarantineVLAN,
		"provisioning_vlan": status.ProvisioningVLAN,
	}, nil
}

// executePXEStartService handles the pxe_start_service tool execution.
func (r *ToolRegistry) executePXEStartService(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	err := pxeSvc.Start(ctx)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": "PXE service started successfully",
	}, nil
}

// executePXEStopService handles the pxe_stop_service tool execution.
func (r *ToolRegistry) executePXEStopService(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	err := pxeSvc.Stop(ctx)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": "PXE service stopped successfully",
	}, nil
}

// executePXEGetDeviceEvents handles the pxe_get_device_events tool execution.
func (r *ToolRegistry) executePXEGetDeviceEvents(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	deviceID := getString(args, "device_id")
	if deviceID == "" {
		return nil, ErrPXEDeviceIDRequired
	}

	events, err := pxeSvc.GetEvents(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"device_id": deviceID,
		"events":    formatEventList(events),
		"count":     len(events),
	}, nil
}

// executePXERemoveDevice handles the pxe_remove_device tool execution.
func (r *ToolRegistry) executePXERemoveDevice(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	deviceID := getString(args, "device_id")
	if deviceID == "" {
		return nil, ErrPXEDeviceIDRequired
	}

	err := pxeSvc.RemoveDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":   true,
		"device_id": deviceID,
		"message":   "device removed from provisioning",
	}, nil
}

// executePXESetDeviceEnrolled handles the pxe_set_device_enrolled tool execution.
func (r *ToolRegistry) executePXESetDeviceEnrolled(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	deviceID := getString(args, "device_id")
	if deviceID == "" {
		return nil, ErrPXEDeviceIDRequired
	}

	certSerial := getString(args, "certificate_serial")
	if certSerial == "" {
		return nil, &PXEError{
			Code:    "PXE_CERT_SERIAL_REQUIRED",
			Message: "certificate_serial is required",
		}
	}

	err := pxeSvc.SetDeviceEnrolled(ctx, deviceID, certSerial)
	if err != nil {
		return nil, err
	}

	device, err := pxeSvc.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	return formatDeviceInfo(device), nil
}

// executePXEWebhookComplete handles the pxe_webhook_complete tool execution.
func (r *ToolRegistry) executePXEWebhookComplete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pxeSvc := r.getPXEService()
	if pxeSvc == nil {
		return nil, ErrPXEServiceUnavailable
	}

	macAddress := getString(args, "mac_address")
	if macAddress == "" {
		return nil, ErrPXEMACAddressRequired
	}

	success := getBool(args, "success")
	hostname := getString(args, "hostname")
	message := getString(args, "message")

	// Look up the device by MAC address
	device, err := pxeSvc.GetDeviceByMAC(ctx, macAddress)
	if err != nil {
		return nil, err
	}

	// Determine the new state based on success
	var newState pxe.ProvisioningState
	var reason string

	if success {
		newState = pxe.StateInstallComplete
		reason = "OS installation completed successfully"
		if hostname != "" {
			reason = fmt.Sprintf("OS installation completed successfully (hostname: %s)", hostname)
		}
	} else {
		newState = pxe.StateFailed
		reason = "OS installation failed"
		if message != "" {
			reason = fmt.Sprintf("OS installation failed: %s", message)
		}
	}

	// Update the device state
	err = pxeSvc.UpdateDeviceState(ctx, device.ID, newState, reason)
	if err != nil {
		return nil, err
	}

	// Get the updated device info
	updatedDevice, err := pxeSvc.GetDevice(ctx, device.ID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"device":  formatDeviceInfo(updatedDevice),
		"message": reason,
	}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// getPXEService returns the PXE service from the service provider.
// This is a placeholder that should be implemented based on the actual
// ServiceProvider interface extension.
func (r *ToolRegistry) getPXEService() pxe.Service {
	// Note: The ServiceProvider interface needs to be extended to include
	// PXE operations, or the PXE service needs to be provided separately.
	// For now, this returns nil and should be implemented based on the
	// actual integration pattern used in the codebase.
	if provider, ok := r.service.(PXEServiceProvider); ok {
		return provider.PXEService()
	}
	return nil
}

// PXEServiceProvider is an interface for accessing the PXE service.
type PXEServiceProvider interface {
	PXEService() pxe.Service
}

// formatDeviceInfo formats a DeviceInfo struct for MCP response.
func formatDeviceInfo(device *pxe.DeviceInfo) map[string]interface{} {
	if device == nil {
		return nil
	}

	result := map[string]interface{}{
		"id":               device.ID,
		"mac_address":      device.MACAddress.String(),
		"port_id":          device.PortID,
		"state":            string(device.State),
		"state_reason":     device.StateReason,
		"current_vlan":     device.CurrentVLAN,
		"target_vlan":      device.TargetVLAN,
		"created_at":       device.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		"updated_at":       device.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		"state_changed_at": device.StateChangedAt.Format("2006-01-02T15:04:05Z07:00"),
		"retry_count":      device.RetryCount,
	}

	if device.CertificateSerial != "" {
		result["certificate_serial"] = device.CertificateSerial
	}

	if device.Profile != nil {
		result["profile"] = map[string]interface{}{
			"id":   device.Profile.ID,
			"name": device.Profile.Name,
		}
	}

	return result
}

// formatDeviceList formats a slice of DeviceInfo for MCP response.
func formatDeviceList(devices []*pxe.DeviceInfo) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(devices))
	for _, device := range devices {
		result = append(result, formatDeviceInfo(device))
	}
	return result
}

// formatEventList formats a slice of ProvisioningEvent for MCP response.
func formatEventList(events []*pxe.ProvisioningEvent) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(events))
	for _, event := range events {
		eventMap := map[string]interface{}{
			"id":         event.ID,
			"device_id":  event.DeviceID,
			"timestamp":  event.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
			"event_type": string(event.EventType),
			"from_state": string(event.FromState),
			"to_state":   string(event.ToState),
		}

		if len(event.Details) > 0 {
			eventMap["details"] = event.Details
		}
		if event.Error != "" {
			eventMap["error"] = event.Error
		}

		result = append(result, eventMap)
	}
	return result
}
