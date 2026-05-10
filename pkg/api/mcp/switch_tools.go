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

	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
)

// =============================================================================
// Switch Service Provider Interface
// =============================================================================

// SwitchMgmtServiceProvider is an interface for accessing the switch service.
type SwitchMgmtServiceProvider interface {
	SwitchService() switchServiceProviderMCP
}

// switchServiceProviderMCP abstracts the switch management service for MCP.
type switchServiceProviderMCP interface {
	Manager(name string) (switchmgmt.Manager, error)
}

// =============================================================================
// Switch Tool Registration
// =============================================================================

// registerSwitchTools registers all physical switch management MCP tools.
func (r *ToolRegistry) registerSwitchTools() {
	r.addTool(ToolDefinition{
		Name:        "switch_list_ports",
		Description: "List all physical ports on a named network switch with their status, VLAN assignments, and link state",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"switch_name": map[string]interface{}{
					"type":        "string",
					"description": "Name of the physical switch (as configured in the platform)",
				},
			},
			"required": []string{"switch_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "switch_port_status",
		Description: "Get the full observable state of a single port on a physical network switch",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"switch_name": map[string]interface{}{
					"type":        "string",
					"description": "Name of the physical switch",
				},
				"port_name": map[string]interface{}{
					"type":        "string",
					"description": "Port name (e.g., Eth1/1, Eth1/3)",
				},
			},
			"required": []string{"switch_name", "port_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "switch_set_vlan",
		Description: "Move an access-mode port to a specified VLAN on a physical network switch",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"switch_name": map[string]interface{}{
					"type":        "string",
					"description": "Name of the physical switch",
				},
				"port_name": map[string]interface{}{
					"type":        "string",
					"description": "Port name (e.g., Eth1/1)",
				},
				"vlan_id": map[string]interface{}{
					"type":        "integer",
					"description": "Target VLAN ID (1-4094)",
				},
			},
			"required": []string{"switch_name", "port_name", "vlan_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "switch_enable_port",
		Description: "Administratively enable a port on a physical network switch",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"switch_name": map[string]interface{}{
					"type":        "string",
					"description": "Name of the physical switch",
				},
				"port_name": map[string]interface{}{
					"type":        "string",
					"description": "Port name (e.g., Eth1/1)",
				},
			},
			"required": []string{"switch_name", "port_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "switch_disable_port",
		Description: "Administratively shut down a port on a physical network switch",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"switch_name": map[string]interface{}{
					"type":        "string",
					"description": "Name of the physical switch",
				},
				"port_name": map[string]interface{}{
					"type":        "string",
					"description": "Port name (e.g., Eth1/1)",
				},
			},
			"required": []string{"switch_name", "port_name"},
		},
	})
}

// =============================================================================
// Switch Tool Execution Handlers
// =============================================================================

// executeSwitchListPorts handles the switch_list_ports tool execution.
func (r *ToolRegistry) executeSwitchListPorts(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := r.getSwitchService()
	if svc == nil {
		return nil, ErrSwitchServiceUnavailable
	}

	switchName := getString(args, "switch_name")
	if switchName == "" {
		return nil, ErrSwitchNameRequired
	}

	mgr, err := svc.Manager(switchName)
	if err != nil {
		return nil, err
	}

	ports, err := mgr.ListPorts(ctx)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"switch": switchName,
		"ports":  formatPortList(ports),
		"count":  len(ports),
	}, nil
}

// executeSwitchPortStatus handles the switch_port_status tool execution.
func (r *ToolRegistry) executeSwitchPortStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := r.getSwitchService()
	if svc == nil {
		return nil, ErrSwitchServiceUnavailable
	}

	switchName := getString(args, "switch_name")
	if switchName == "" {
		return nil, ErrSwitchNameRequired
	}

	portName := getString(args, "port_name")
	if portName == "" {
		return nil, ErrSwitchPortNameRequired
	}

	mgr, err := svc.Manager(switchName)
	if err != nil {
		return nil, err
	}

	status, err := mgr.GetPortStatus(ctx, portName)
	if err != nil {
		return nil, err
	}

	return formatPortStatus(status), nil
}

// executeSwitchSetVLAN handles the switch_set_vlan tool execution.
func (r *ToolRegistry) executeSwitchSetVLAN(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := r.getSwitchService()
	if svc == nil {
		return nil, ErrSwitchServiceUnavailable
	}

	switchName := getString(args, "switch_name")
	if switchName == "" {
		return nil, ErrSwitchNameRequired
	}

	portName := getString(args, "port_name")
	if portName == "" {
		return nil, ErrSwitchPortNameRequired
	}

	vlanID := getInt(args, "vlan_id")
	if vlanID < 1 || vlanID > 4094 {
		return nil, ErrSwitchInvalidVLAN
	}

	mgr, err := svc.Manager(switchName)
	if err != nil {
		return nil, err
	}

	if err := mgr.SetPortVLAN(ctx, portName, uint16(vlanID)); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"switch":  switchName,
		"port":    portName,
		"vlan_id": vlanID,
		"message": "port VLAN updated successfully",
	}, nil
}

// executeSwitchEnablePort handles the switch_enable_port tool execution.
func (r *ToolRegistry) executeSwitchEnablePort(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := r.getSwitchService()
	if svc == nil {
		return nil, ErrSwitchServiceUnavailable
	}

	switchName := getString(args, "switch_name")
	if switchName == "" {
		return nil, ErrSwitchNameRequired
	}

	portName := getString(args, "port_name")
	if portName == "" {
		return nil, ErrSwitchPortNameRequired
	}

	mgr, err := svc.Manager(switchName)
	if err != nil {
		return nil, err
	}

	if err := mgr.EnablePort(ctx, portName); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"switch":  switchName,
		"port":    portName,
		"action":  "enable",
		"message": "port enabled successfully",
	}, nil
}

// executeSwitchDisablePort handles the switch_disable_port tool execution.
func (r *ToolRegistry) executeSwitchDisablePort(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := r.getSwitchService()
	if svc == nil {
		return nil, ErrSwitchServiceUnavailable
	}

	switchName := getString(args, "switch_name")
	if switchName == "" {
		return nil, ErrSwitchNameRequired
	}

	portName := getString(args, "port_name")
	if portName == "" {
		return nil, ErrSwitchPortNameRequired
	}

	mgr, err := svc.Manager(switchName)
	if err != nil {
		return nil, err
	}

	if err := mgr.DisablePort(ctx, portName); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"switch":  switchName,
		"port":    portName,
		"action":  "disable",
		"message": "port disabled successfully",
	}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// getSwitchService returns the switch service from the service provider.
func (r *ToolRegistry) getSwitchService() switchServiceProviderMCP {
	if provider, ok := r.service.(SwitchMgmtServiceProvider); ok {
		return provider.SwitchService()
	}
	return nil
}

// formatPortStatus formats a PortStatus struct for MCP response.
func formatPortStatus(ps *switchmgmt.PortStatus) map[string]interface{} {
	if ps == nil {
		return nil
	}

	result := map[string]interface{}{
		"port":        ps.Port,
		"mode":        string(ps.Mode),
		"access_vlan": ps.AccessVLAN,
		"enabled":     ps.Enabled,
		"link_up":     ps.LinkUp,
	}

	if len(ps.TrunkVLANs) > 0 {
		vlans := make([]int, 0, len(ps.TrunkVLANs))
		for _, v := range ps.TrunkVLANs {
			vlans = append(vlans, int(v))
		}
		result["trunk_vlans"] = vlans
	}

	if ps.Description != "" {
		result["description"] = ps.Description
	}

	return result
}

// formatPortList formats a slice of PortStatus for MCP response.
func formatPortList(ports []*switchmgmt.PortStatus) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(ports))
	for _, p := range ports {
		result = append(result, formatPortStatus(p))
	}
	return result
}

// =============================================================================
// Switch Error Types
// =============================================================================

// ErrSwitchServiceUnavailable indicates the switch service is not available.
var ErrSwitchServiceUnavailable = &SwitchError{
	Code:    "SWITCH_SERVICE_UNAVAILABLE",
	Message: "physical switch management service is not available",
}

// ErrSwitchNameRequired indicates a switch name is required.
var ErrSwitchNameRequired = &SwitchError{
	Code:    "SWITCH_NAME_REQUIRED",
	Message: "switch_name is required",
}

// ErrSwitchPortNameRequired indicates a port name is required.
var ErrSwitchPortNameRequired = &SwitchError{
	Code:    "SWITCH_PORT_NAME_REQUIRED",
	Message: "port_name is required",
}

// ErrSwitchInvalidVLAN indicates an invalid VLAN ID.
var ErrSwitchInvalidVLAN = &SwitchError{
	Code:    "SWITCH_INVALID_VLAN",
	Message: "vlan_id must be between 1 and 4094",
}

// SwitchError represents a switch operation error.
type SwitchError struct {
	Code    string
	Message string
}

func (e *SwitchError) Error() string {
	return e.Code + ": " + e.Message
}
