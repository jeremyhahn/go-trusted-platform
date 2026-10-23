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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Overlay Error Types
// =============================================================================

// OverlayError represents an overlay network operation error.
type OverlayError struct {
	Code    string
	Message string
}

func (e *OverlayError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *OverlayError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
}

// ErrOverlayServiceUnavailable indicates the overlay service is not available.
var ErrOverlayServiceUnavailable = &OverlayError{
	Code:    "OVERLAY_SERVICE_UNAVAILABLE",
	Message: "overlay service is not available",
}

// ErrOverlayControllerNotRunning indicates the overlay controller is not running.
var ErrOverlayControllerNotRunning = &OverlayError{
	Code:    "OVERLAY_CONTROLLER_NOT_RUNNING",
	Message: "overlay controller is not running",
}

// ErrOverlayNodeIDRequired indicates a node ID is required.
var ErrOverlayNodeIDRequired = &OverlayError{
	Code:    "OVERLAY_NODE_ID_REQUIRED",
	Message: "node ID is required",
}

// ErrOverlayVNIRequired indicates a VNI is required.
var ErrOverlayVNIRequired = &OverlayError{
	Code:    "OVERLAY_VNI_REQUIRED",
	Message: "VNI is required",
}

// ErrOverlayMACRequired indicates a MAC address is required.
var ErrOverlayMACRequired = &OverlayError{
	Code:    "OVERLAY_MAC_REQUIRED",
	Message: "MAC address is required",
}

// ErrOverlayVTEPNotFound indicates a VTEP was not found.
var ErrOverlayVTEPNotFound = &OverlayError{
	Code:    "OVERLAY_VTEP_NOT_FOUND",
	Message: "VTEP not found",
}

// ErrOverlayVNINotFound indicates a VNI was not found.
var ErrOverlayVNINotFound = &OverlayError{
	Code:    "OVERLAY_VNI_NOT_FOUND",
	Message: "VNI not found",
}

// ErrOverlayInvalidVNI indicates an invalid VNI value.
var ErrOverlayInvalidVNI = &OverlayError{
	Code:    "OVERLAY_INVALID_VNI",
	Message: "invalid VNI value",
}

// ErrOverlayInvalidMAC indicates an invalid MAC address.
var ErrOverlayInvalidMAC = &OverlayError{
	Code:    "OVERLAY_INVALID_MAC",
	Message: "invalid MAC address",
}

// maxOverlayVLAN is the highest VLAN ID a VNI may map to.
const maxOverlayVLAN = 4094

// ErrOverlayInvalidVLAN indicates a VLAN ID outside 0-4094.
var ErrOverlayInvalidVLAN = &OverlayError{
	Code:    "OVERLAY_INVALID_VLAN",
	Message: "invalid VLAN ID",
}

// ErrOverlayVNIAlreadyExists indicates the VNI is already configured.
var ErrOverlayVNIAlreadyExists = &OverlayError{
	Code:    "OVERLAY_VNI_ALREADY_EXISTS",
	Message: "VNI already exists",
}

// ErrOverlayMACNotFound indicates the MAC address is not in the forwarding table.
var ErrOverlayMACNotFound = &OverlayError{
	Code:    "OVERLAY_MAC_NOT_FOUND",
	Message: "MAC address not found",
}

// ErrOverlayTunnelNotFound indicates no tunnel matches the remote VTEP and VNI.
var ErrOverlayTunnelNotFound = &OverlayError{
	Code:    "OVERLAY_TUNNEL_NOT_FOUND",
	Message: "tunnel not found",
}

// ErrOverlayRemoteVTEPRequired indicates a remote VTEP address is required.
var ErrOverlayRemoteVTEPRequired = &OverlayError{
	Code:    "OVERLAY_REMOTE_VTEP_REQUIRED",
	Message: "remote VTEP address is required",
}

// ErrOverlayInvalidRemoteVTEP indicates the remote VTEP is not an IP address.
var ErrOverlayInvalidRemoteVTEP = &OverlayError{
	Code:    "OVERLAY_INVALID_REMOTE_VTEP",
	Message: "invalid remote VTEP address",
}

// =============================================================================
// Overlay Tool Registration
// =============================================================================

// registerOverlayTools registers overlay network MCP tools.
func (r *ToolRegistry) registerOverlayTools() {
	// Overlay status
	r.addTool(mcpwire.ToolDefinition{
		Name:        "overlay_status",
		Description: "Get the current status of the overlay network including node ID, VTEP IP, and counts of VTEPs, VNIs, tunnels, and remote MACs",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// VTEP operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "overlay_vtep_list",
		Description: "List all known VTEP (Virtual Tunnel End Point) endpoints in the overlay network",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "overlay_vtep_get",
		Description: "Get detailed information about a specific VTEP by its node ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"node_id": map[string]interface{}{
					"type":        "string",
					"description": "The node ID of the VTEP to retrieve",
				},
			},
			"required": []string{"node_id"},
		},
	})

	// VNI operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "overlay_vni_list",
		Description: "List all configured VNIs (Virtual Network Identifiers) in the overlay network",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "overlay_vni_create",
		Description: "Create a new VNI (Virtual Network Identifier) for overlay network segmentation",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vni": map[string]interface{}{
					"type":        "integer",
					"description": "The VNI number (1-16777215)",
				},
				"vlan": map[string]interface{}{
					"type":        "integer",
					"description": "The VLAN ID to map to this VNI (0-4094)",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Optional human-readable name for the VNI; accepted but not stored",
				},
			},
			"required": []string{"vni"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "overlay_vni_delete",
		Description: "Delete a VNI from the overlay network",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vni": map[string]interface{}{
					"type":        "integer",
					"description": "The VNI number to delete",
				},
			},
			"required": []string{"vni"},
		},
	})

	// Tunnel operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "overlay_tunnel_list",
		Description: "List all VXLAN tunnels in the overlay network with optional VNI filter",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vni": map[string]interface{}{
					"type":        "integer",
					"description": "Optional VNI to filter tunnels by",
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "overlay_tunnel_stats",
		Description: "Get the traffic counters of the VXLAN tunnel to a remote VTEP, optionally for one VNI",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"remote_vtep": map[string]interface{}{
					"type":        "string",
					"description": "The remote VTEP IP address",
				},
				"vni": map[string]interface{}{
					"type":        "integer",
					"description": "Optional VNI; 0 or omitted selects the first tunnel to the remote VTEP",
				},
			},
			"required": []string{"remote_vtep"},
		},
	})

	// MAC operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "overlay_mac_list",
		Description: "List learned remote MAC addresses in the overlay network with optional VNI filter",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vni": map[string]interface{}{
					"type":        "integer",
					"description": "Optional VNI to filter MAC addresses by",
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "overlay_mac_forget",
		Description: "Remove a learned MAC address from the forwarding table",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"mac": map[string]interface{}{
					"type":        "string",
					"description": "The MAC address to forget (e.g., 00:11:22:33:44:55)",
				},
				"vni": map[string]interface{}{
					"type":        "integer",
					"description": "The VNI the MAC address belongs to",
				},
			},
			"required": []string{"mac", "vni"},
		},
	})
}

// =============================================================================
// Overlay Tool Execution Handlers
// =============================================================================

func (r *ToolRegistry) executeOverlayStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.OverlayStatus(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeOverlayVTEPList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	vteps, err := r.service.OverlayVTEPList(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"vteps": vteps}, nil
}

func (r *ToolRegistry) executeOverlayVTEPGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	nodeID := getString(args, "node_id")
	if nodeID == "" {
		return nil, ErrOverlayNodeIDRequired
	}

	vtep, err := r.service.OverlayVTEPGet(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	return marshalResult(vtep)
}

func (r *ToolRegistry) executeOverlayVNIList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	vnis, err := r.service.OverlayVNIList(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"vnis": vnis}, nil
}

func (r *ToolRegistry) executeOverlayVNICreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	vni := getInt(args, "vni")
	if vni == 0 {
		return nil, ErrOverlayVNIRequired
	}

	vlan := getInt(args, "vlan")
	if vlan < 0 || vlan > maxOverlayVLAN {
		return nil, ErrOverlayInvalidVLAN
	}
	name := getString(args, "name")

	result, err := r.service.OverlayVNICreate(ctx, uint32(vni), uint16(vlan), name)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeOverlayVNIDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	vni := getInt(args, "vni")
	if vni == 0 {
		return nil, ErrOverlayVNIRequired
	}

	if err := r.service.OverlayVNIDelete(ctx, uint32(vni)); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeOverlayTunnelList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	vni := getInt(args, "vni")

	tunnels, err := r.service.OverlayTunnelList(ctx, uint32(vni))
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"tunnels": tunnels}, nil
}

func (r *ToolRegistry) executeOverlayTunnelStats(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	remoteVTEP := getString(args, "remote_vtep")
	if remoteVTEP == "" {
		return nil, ErrOverlayRemoteVTEPRequired
	}

	vni := getInt(args, "vni")
	if vni < 0 {
		return nil, ErrOverlayInvalidVNI
	}

	tunnel, err := r.service.OverlayTunnelStats(ctx, remoteVTEP, uint32(vni))
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"tunnel": tunnel}, nil
}

func (r *ToolRegistry) executeOverlayMACList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	vni := getInt(args, "vni")

	macs, err := r.service.OverlayMACList(ctx, uint32(vni))
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"macs": macs}, nil
}

func (r *ToolRegistry) executeOverlayMACForget(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mac := getString(args, "mac")
	if mac == "" {
		return nil, ErrOverlayMACRequired
	}

	vni := getInt(args, "vni")
	if vni == 0 {
		return nil, ErrOverlayVNIRequired
	}

	if err := r.service.OverlayMACForget(ctx, mac, uint32(vni)); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}
