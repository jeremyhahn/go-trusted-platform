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
)

// =============================================================================
// Gateway Error Types
// =============================================================================

// GatewayError represents a gateway operation error.
type GatewayError struct {
	Code    string
	Message string
}

func (e *GatewayError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ErrGatewayServiceUnavailable indicates the gateway service is not available.
var ErrGatewayServiceUnavailable = &GatewayError{
	Code:    "GATEWAY_SERVICE_UNAVAILABLE",
	Message: "gateway service is not available",
}

// ErrGatewayNotRunning indicates the gateway is not running.
var ErrGatewayNotRunning = &GatewayError{
	Code:    "GATEWAY_NOT_RUNNING",
	Message: "gateway is not running",
}

// ErrGatewayModesRequired indicates gateway modes are required.
var ErrGatewayModesRequired = &GatewayError{
	Code:    "GATEWAY_MODES_REQUIRED",
	Message: "gateway modes are required",
}

// ErrBGPServiceUnavailable indicates the BGP service is not available.
var ErrBGPServiceUnavailable = &GatewayError{
	Code:    "BGP_SERVICE_UNAVAILABLE",
	Message: "BGP service is not available",
}

// ErrBGPNotRunning indicates the BGP speaker is not running.
var ErrBGPNotRunning = &GatewayError{
	Code:    "BGP_NOT_RUNNING",
	Message: "BGP speaker is not running",
}

// ErrBGPPrefixRequired indicates a BGP prefix is required.
var ErrBGPPrefixRequired = &GatewayError{
	Code:    "BGP_PREFIX_REQUIRED",
	Message: "BGP prefix is required",
}

// ErrBGPInvalidPrefix indicates an invalid BGP prefix.
var ErrBGPInvalidPrefix = &GatewayError{
	Code:    "BGP_INVALID_PREFIX",
	Message: "invalid BGP prefix",
}

// ErrBGPInvalidNextHop indicates an invalid BGP next hop address.
var ErrBGPInvalidNextHop = &GatewayError{
	Code:    "BGP_INVALID_NEXT_HOP",
	Message: "invalid BGP next hop address",
}

// ErrIPAMServiceUnavailable indicates the IPAM service is not available.
var ErrIPAMServiceUnavailable = &GatewayError{
	Code:    "IPAM_SERVICE_UNAVAILABLE",
	Message: "IPAM service is not available",
}

// ErrIPAMPoolIDRequired indicates a pool ID is required.
var ErrIPAMPoolIDRequired = &GatewayError{
	Code:    "IPAM_POOL_ID_REQUIRED",
	Message: "pool ID is required",
}

// ErrIPAMPoolNameRequired indicates a pool name is required.
var ErrIPAMPoolNameRequired = &GatewayError{
	Code:    "IPAM_POOL_NAME_REQUIRED",
	Message: "pool name is required",
}

// ErrIPAMPoolCIDRRequired indicates a pool CIDR is required.
var ErrIPAMPoolCIDRRequired = &GatewayError{
	Code:    "IPAM_POOL_CIDR_REQUIRED",
	Message: "pool CIDR is required",
}

// ErrIPAMDeviceIDRequired indicates a device ID is required.
var ErrIPAMDeviceIDRequired = &GatewayError{
	Code:    "IPAM_DEVICE_ID_REQUIRED",
	Message: "device ID is required",
}

// ErrIPAMIPRequired indicates an IP address is required.
var ErrIPAMIPRequired = &GatewayError{
	Code:    "IPAM_IP_REQUIRED",
	Message: "IP address is required",
}

// ErrIPAMInvalidIP indicates an invalid IP address.
var ErrIPAMInvalidIP = &GatewayError{
	Code:    "IPAM_INVALID_IP",
	Message: "invalid IP address",
}

// ErrIPAMPoolNotFound indicates an IPAM pool was not found.
var ErrIPAMPoolNotFound = &GatewayError{
	Code:    "IPAM_POOL_NOT_FOUND",
	Message: "IPAM pool not found",
}

// ErrIPAMAllocationFailed indicates an IP allocation failed.
var ErrIPAMAllocationFailed = &GatewayError{
	Code:    "IPAM_ALLOCATION_FAILED",
	Message: "IP allocation failed",
}

// =============================================================================
// Gateway Tool Registration
// =============================================================================

// registerGatewayTools registers gateway MCP tools.
func (r *ToolRegistry) registerGatewayTools() {
	// Gateway status and mode operations
	r.addTool(ToolDefinition{
		Name:        "gateway_status",
		Description: "Get the current status of the gateway including ID, node ID, active modes, tier, reputation, and health status",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_mode_set",
		Description: "Set the active gateway modes. Modes determine gateway capabilities (e.g., router, NAT, firewall)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"modes": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "string",
					},
					"description": "Array of mode names to activate (e.g., ['router', 'nat', 'firewall'])",
				},
			},
			"required": []string{"modes"},
		},
	})

	// BGP operations
	r.addTool(ToolDefinition{
		Name:        "gateway_bgp_status",
		Description: "Get the current status of the BGP speaker including local ASN, router ID, peer counts, and announced prefixes",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_bgp_peers",
		Description: "List all configured BGP peers with their state, ASN, and prefix statistics",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_bgp_announce",
		Description: "Announce a network prefix via BGP to advertise reachability",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"prefix": map[string]interface{}{
					"type":        "string",
					"description": "The network prefix to announce in CIDR notation (e.g., 10.0.0.0/24)",
				},
				"next_hop": map[string]interface{}{
					"type":        "string",
					"description": "Optional next hop IP address for the prefix",
				},
			},
			"required": []string{"prefix"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_bgp_withdraw",
		Description: "Withdraw a previously announced network prefix from BGP",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"prefix": map[string]interface{}{
					"type":        "string",
					"description": "The network prefix to withdraw in CIDR notation (e.g., 10.0.0.0/24)",
				},
			},
			"required": []string{"prefix"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_bgp_prefixes",
		Description: "List all network prefixes currently being announced via BGP",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// IPAM operations
	r.addTool(ToolDefinition{
		Name:        "gateway_ipam_pools",
		Description: "List all IPAM (IP Address Management) pools with their CIDR, gateway, and allocation statistics",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_ipam_pool_create",
		Description: "Create a new IPAM pool with a name, CIDR range, optional gateway, DNS servers, and lease duration",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Name for the IPAM pool",
				},
				"cidr": map[string]interface{}{
					"type":        "string",
					"description": "CIDR range for the pool (e.g., 10.0.0.0/24)",
				},
				"gateway": map[string]interface{}{
					"type":        "string",
					"description": "Optional gateway IP address for the pool",
				},
				"dns": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Optional DNS server addresses for the pool",
				},
				"lease_duration_seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Optional lease duration in seconds",
				},
			},
			"required": []string{"name", "cidr"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_ipam_pool_delete",
		Description: "Delete an IPAM pool by its ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pool_id": map[string]interface{}{
					"type":        "string",
					"description": "The ID of the IPAM pool to delete",
				},
			},
			"required": []string{"pool_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_ipam_allocate",
		Description: "Allocate an IP address from an IPAM pool for a device",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pool_id": map[string]interface{}{
					"type":        "string",
					"description": "The ID of the IPAM pool to allocate from",
				},
				"device_id": map[string]interface{}{
					"type":        "string",
					"description": "The ID of the device requesting the allocation",
				},
				"hostname": map[string]interface{}{
					"type":        "string",
					"description": "Optional hostname to associate with the allocation",
				},
			},
			"required": []string{"pool_id", "device_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_ipam_release",
		Description: "Release an allocated IP address back to its pool",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ip": map[string]interface{}{
					"type":        "string",
					"description": "The IP address to release (e.g., 10.0.0.5)",
				},
			},
			"required": []string{"ip"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_ipam_allocations",
		Description: "List all IP allocations with optional filtering by pool ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pool_id": map[string]interface{}{
					"type":        "string",
					"description": "Optional pool ID to filter allocations by",
				},
			},
		},
	})
}

// =============================================================================
// Gateway Tool Execution Handlers
// =============================================================================

func (r *ToolRegistry) executeGatewayStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.GatewayStatus(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayModeSet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	modes := getStringSlice(args, "modes")
	if len(modes) == 0 {
		return nil, ErrGatewayModesRequired
	}

	result, err := r.service.GatewayModeSet(ctx, modes)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayBGPStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.GatewayBGPStatus(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayBGPPeers(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	peers, err := r.service.GatewayBGPPeers(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"peers": peers}, nil
}

func (r *ToolRegistry) executeGatewayBGPAnnounce(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	prefix := getString(args, "prefix")
	if prefix == "" {
		return nil, ErrBGPPrefixRequired
	}

	nextHop := getString(args, "next_hop")

	if err := r.service.GatewayBGPAnnounce(ctx, prefix, nextHop); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeGatewayBGPWithdraw(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	prefix := getString(args, "prefix")
	if prefix == "" {
		return nil, ErrBGPPrefixRequired
	}

	if err := r.service.GatewayBGPWithdraw(ctx, prefix); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeGatewayBGPPrefixes(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	prefixes, err := r.service.GatewayBGPPrefixes(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"prefixes": prefixes}, nil
}

func (r *ToolRegistry) executeGatewayIPAMPools(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pools, err := r.service.GatewayIPAMPools(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"pools": pools}, nil
}

func (r *ToolRegistry) executeGatewayIPAMPoolCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, ErrIPAMPoolNameRequired
	}

	cidr := getString(args, "cidr")
	if cidr == "" {
		return nil, ErrIPAMPoolCIDRRequired
	}

	req := &IPAMPoolCreateRequest{
		Name:                 name,
		CIDR:                 cidr,
		Gateway:              getString(args, "gateway"),
		DNS:                  getStringSlice(args, "dns"),
		LeaseDurationSeconds: getInt64(args, "lease_duration_seconds"),
	}

	result, err := r.service.GatewayIPAMPoolCreate(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayIPAMPoolDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	poolID := getString(args, "pool_id")
	if poolID == "" {
		return nil, ErrIPAMPoolIDRequired
	}

	if err := r.service.GatewayIPAMPoolDelete(ctx, poolID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeGatewayIPAMAllocate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	poolID := getString(args, "pool_id")
	if poolID == "" {
		return nil, ErrIPAMPoolIDRequired
	}

	deviceID := getString(args, "device_id")
	if deviceID == "" {
		return nil, ErrIPAMDeviceIDRequired
	}

	hostname := getString(args, "hostname")

	result, err := r.service.GatewayIPAMAllocate(ctx, poolID, deviceID, hostname)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayIPAMRelease(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ip := getString(args, "ip")
	if ip == "" {
		return nil, ErrIPAMIPRequired
	}

	if err := r.service.GatewayIPAMRelease(ctx, ip); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeGatewayIPAMAllocations(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	poolID := getString(args, "pool_id")

	allocations, err := r.service.GatewayIPAMAllocations(ctx, poolID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"allocations": allocations}, nil
}
