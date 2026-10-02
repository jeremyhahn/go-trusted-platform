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

// ErrNetworkZoneNameRequired indicates a zone name is required.
var ErrNetworkZoneNameRequired = &GatewayError{
	Code:    "NETWORK_ZONE_NAME_REQUIRED",
	Message: "zone name is required",
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
		Name: "gateway_snapshot",
		Description: "Get one gateway's telemetry snapshot: BGP sessions with their BFD state and prefix counters, " +
			"tunnels, uplink policy routes, the nftables host filter, NAT, the base OVS pipeline and every " +
			"service's active/healthy state. Omit gateway_id to read the gateway this node runs itself",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"gateway_id": map[string]interface{}{
					"type":        "string",
					"description": "The reporting gateway's id; omit for this node's own gateway",
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_snapshots",
		Description: "List the telemetry snapshots of every gateway that has reported to this control plane, newest report first",
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
		Description: "List IPAM (IP Address Management) pools with their CIDR, gateway, and allocation statistics; optionally filter by zone",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"zone": map[string]interface{}{
					"type":        "string",
					"description": "Optional zone filter (e.g. 'control-plane', 'provisioning'); empty returns all pools",
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_ipam_pool_get",
		Description: "Get details of a specific IPAM pool by its ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pool_id": map[string]interface{}{
					"type":        "string",
					"description": "The ID of the IPAM pool to retrieve",
				},
			},
			"required": []string{"pool_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_ipam_pool_create",
		Description: "Create a new IPAM pool with a name, CIDR range, optional gateway, zone, DNS servers, and lease duration",
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
				"zone": map[string]interface{}{
					"type":        "string",
					"description": "Optional underlay zone the pool serves (e.g., control-plane)",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "Optional human-readable pool description",
				},
				"lease_duration_seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Optional lease duration in seconds",
				},
				"reserved": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Optional prefixes (CIDR) that are never allocatable; the gateway is always reserved",
				},
				"range_start": map[string]interface{}{
					"type":        "string",
					"description": "Optional first address of the dynamic allocation window (set with range_end)",
				},
				"range_end": map[string]interface{}{
					"type":        "string",
					"description": "Optional last address of the dynamic allocation window (set with range_start)",
				},
			},
			"required": []string{"name", "cidr"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_ipam_pool_update",
		Description: "Update mutable fields of an existing IPAM pool. CIDR cannot be changed after creation.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pool_id": map[string]interface{}{
					"type":        "string",
					"description": "The ID of the IPAM pool to update",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Updated display name for the pool",
				},
				"gateway": map[string]interface{}{
					"type":        "string",
					"description": "Updated gateway IP address",
				},
				"zone": map[string]interface{}{
					"type":        "string",
					"description": "Updated zone (e.g. 'control-plane', 'provisioning')",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "Updated description",
				},
				"lease_duration_seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Updated lease duration in seconds (0 = never expire)",
				},
				"reserved": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Replacement never-allocatable prefixes (CIDR); an empty list clears them, omitted keeps them",
				},
				"range_start": map[string]interface{}{
					"type":        "string",
					"description": "Replacement first address of the dynamic window; \"\" clears it, omitted keeps it",
				},
				"range_end": map[string]interface{}{
					"type":        "string",
					"description": "Replacement last address of the dynamic window; \"\" clears it, omitted keeps it",
				},
			},
			"required": []string{"pool_id"},
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
	r.registerGatewayZoneTools()
}

// registerGatewayZoneTools registers MCP tools for the underlay zones of the
// reference network: the built-in zones (policy tunable, numbering fixed)
// and owner-defined zones at offsets 9-99.
func (r *ToolRegistry) registerGatewayZoneTools() {
	r.addTool(ToolDefinition{
		Name:        "gateway_zone_list",
		Description: "List the underlay network zones with their policy and derived numbering (VLAN, subnets), optionally filtered by lifecycle role",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"lifecycle_role": map[string]interface{}{
					"type":        "string",
					"description": "Optional filter: provisioning, quarantine (empty returns all)",
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_zone_create",
		Description: "Create an owner-defined underlay zone (offset 9-99, gateway and/or hypervisor port class). Returns restart_required: the network plan is derived at daemon startup.",
		InputSchema: map[string]interface{}{
			"type":     "object",
			"required": []string{"name", "offset", "port_classes"},
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Unique zone name (not platform, tenant, public or trusted: overlays are not zones)",
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"description": "Offset in the environment block: 9-99 for an owner-defined zone (built-in offsets 0-8 are fixed)",
				},
				"port_classes": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Switch port classes carrying the zone (owner-defined zones: gateway and/or hypervisor; fixed for built-ins)",
				},
				"internet_ingress": map[string]interface{}{
					"type":        "boolean",
					"description": "Zone accepts internet ingress traffic",
				},
				"isolate_from": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Zones this zone never sends to, even when allow_to would open the path",
				},
				"allow_to": map[string]interface{}{
					"type":        "array",
					"description": "Directed paths to other zones; an empty services list allows all services",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"zone":     map[string]interface{}{"type": "string"},
							"services": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						},
						"required": []string{"zone"},
					},
				},
				"services": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Services permitted within the zone",
				},
				"isolate": map[string]interface{}{
					"type":        "boolean",
					"description": "Deny all traffic except explicit allow_to paths",
				},
				"oob": map[string]interface{}{
					"type":        "boolean",
					"description": "Out-of-band management zone (built-in management only)",
				},
				"lifecycle_role": map[string]interface{}{
					"type":        "string",
					"description": "Lifecycle role (built-in provisioning and quarantine only)",
				},
				"privileged_access": map[string]interface{}{
					"type":        "object",
					"description": "Audited override required for an allow_to path into control-plane or management beyond the reference defaults",
					"properties": map[string]interface{}{
						"reason":      map[string]interface{}{"type": "string"},
						"approved_by": map[string]interface{}{"type": "string"},
					},
					"required": []string{"reason", "approved_by"},
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_zone_update",
		Description: "Tune a built-in zone's policy or replace an owner-defined zone. Built-in identity (offset, port classes, lifecycle role, oob) cannot change. Returns restart_required.",
		InputSchema: map[string]interface{}{
			"type":     "object",
			"required": []string{"name"},
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Name of the zone to update",
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"description": "Offset in the environment block: 9-99 for an owner-defined zone (built-in offsets 0-8 are fixed)",
				},
				"port_classes": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Switch port classes carrying the zone (owner-defined zones: gateway and/or hypervisor; fixed for built-ins)",
				},
				"internet_ingress": map[string]interface{}{
					"type":        "boolean",
					"description": "Zone accepts internet ingress traffic",
				},
				"isolate_from": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Zones this zone never sends to, even when allow_to would open the path",
				},
				"allow_to": map[string]interface{}{
					"type":        "array",
					"description": "Directed paths to other zones; an empty services list allows all services",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"zone":     map[string]interface{}{"type": "string"},
							"services": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						},
						"required": []string{"zone"},
					},
				},
				"services": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Services permitted within the zone",
				},
				"isolate": map[string]interface{}{
					"type":        "boolean",
					"description": "Deny all traffic except explicit allow_to paths",
				},
				"oob": map[string]interface{}{
					"type":        "boolean",
					"description": "Out-of-band management zone (built-in management only)",
				},
				"lifecycle_role": map[string]interface{}{
					"type":        "string",
					"description": "Lifecycle role (built-in provisioning and quarantine only)",
				},
				"privileged_access": map[string]interface{}{
					"type":        "object",
					"description": "Audited override required for an allow_to path into control-plane or management beyond the reference defaults",
					"properties": map[string]interface{}{
						"reason":      map[string]interface{}{"type": "string"},
						"approved_by": map[string]interface{}{"type": "string"},
					},
					"required": []string{"reason", "approved_by"},
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_zone_delete",
		Description: "Delete an owner-defined zone or omit an optional built-in. fabric, provisioning, quarantine and control-plane cannot be removed.",
		InputSchema: map[string]interface{}{
			"type":     "object",
			"required": []string{"name"},
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Name of the zone to delete",
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

func (r *ToolRegistry) executeGatewaySnapshot(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.GatewaySnapshot(ctx, getString(args, "gateway_id"))
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewaySnapshots(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	snapshots, err := r.service.GatewaySnapshots(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"snapshots": snapshots}, nil
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
	zone := getString(args, "zone")
	pools, err := r.service.GatewayIPAMPools(ctx, zone)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"pools": pools}, nil
}

func (r *ToolRegistry) executeGatewayIPAMPoolGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	poolID := getString(args, "pool_id")
	if poolID == "" {
		return nil, ErrIPAMPoolIDRequired
	}

	result, err := r.service.GatewayIPAMPoolGet(ctx, poolID)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
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
		Zone:                 getString(args, "zone"),
		Description:          getString(args, "description"),
		LeaseDurationSeconds: getInt64(args, "lease_duration_seconds"),
		Reserved:             getStringSlice(args, "reserved"),
		RangeStart:           getString(args, "range_start"),
		RangeEnd:             getString(args, "range_end"),
	}

	result, err := r.service.GatewayIPAMPoolCreate(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayIPAMPoolUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	poolID := getString(args, "pool_id")
	if poolID == "" {
		return nil, ErrIPAMPoolIDRequired
	}

	req := &IPAMPoolUpdateRequest{
		Name:                 getString(args, "name"),
		Gateway:              getString(args, "gateway"),
		Zone:                 getString(args, "zone"),
		Description:          getString(args, "description"),
		LeaseDurationSeconds: getInt64(args, "lease_duration_seconds"),
		Reserved:             getStringSlice(args, "reserved"),
		RangeStart:           getOptionalString(args, "range_start"),
		RangeEnd:             getOptionalString(args, "range_end"),
	}

	result, err := r.service.GatewayIPAMPoolUpdate(ctx, poolID, req)
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

// =============================================================================
// Network Zone Execute Functions
// =============================================================================

func (r *ToolRegistry) executeGatewayZoneList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	lifecycleRole := getString(args, "lifecycle_role")
	zones, err := r.service.GatewayNetworkZoneList(ctx, lifecycleRole)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"zones": zones}, nil
}

func (r *ToolRegistry) executeGatewayZoneCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, ErrNetworkZoneNameRequired
	}
	req := &NetworkZoneCreateRequest{
		Name:             name,
		Offset:           uint8(getInt(args, "offset")),
		PortClasses:      getStringSlice(args, "port_classes"),
		InternetIngress:  getBool(args, "internet_ingress"),
		IsolateFrom:      getStringSlice(args, "isolate_from"),
		AllowTo:          getZonePaths(args, "allow_to"),
		Services:         getStringSlice(args, "services"),
		Isolate:          getBool(args, "isolate"),
		OOB:              getBool(args, "oob"),
		LifecycleRole:    getString(args, "lifecycle_role"),
		PrivilegedAccess: getPrivilegedAccess(args, "privileged_access"),
	}
	result, err := r.service.GatewayNetworkZoneCreate(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayZoneUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, ErrNetworkZoneNameRequired
	}
	req := &NetworkZoneUpdateRequest{
		Offset:           uint8(getInt(args, "offset")),
		PortClasses:      getStringSlice(args, "port_classes"),
		InternetIngress:  getBool(args, "internet_ingress"),
		IsolateFrom:      getStringSlice(args, "isolate_from"),
		AllowTo:          getZonePaths(args, "allow_to"),
		Services:         getStringSlice(args, "services"),
		Isolate:          getBool(args, "isolate"),
		OOB:              getBool(args, "oob"),
		LifecycleRole:    getString(args, "lifecycle_role"),
		PrivilegedAccess: getPrivilegedAccess(args, "privileged_access"),
	}
	result, err := r.service.GatewayNetworkZoneUpdate(ctx, name, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// getZonePaths reads an allow_to argument: a list of {zone, services}
// objects. Entries that are not objects or have no zone are skipped.
func getZonePaths(args map[string]interface{}, key string) []*NetworkZonePathRequest {
	items, ok := args[key].([]interface{})
	if !ok {
		return nil
	}
	var out []*NetworkZonePathRequest
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		z := getString(m, "zone")
		if z == "" {
			continue
		}
		out = append(out, &NetworkZonePathRequest{Zone: z, Services: getStringSlice(m, "services")})
	}
	return out
}

// getPrivilegedAccess reads a privileged_access argument object.
func getPrivilegedAccess(args map[string]interface{}, key string) *NetworkZonePrivilegedAccessRequest {
	m := getMap(args, key)
	if m == nil {
		return nil
	}
	return &NetworkZonePrivilegedAccessRequest{
		Reason:     getString(m, "reason"),
		ApprovedBy: getString(m, "approved_by"),
	}
}

func (r *ToolRegistry) executeGatewayZoneDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, ErrNetworkZoneNameRequired
	}
	restartRequired, err := r.service.GatewayNetworkZoneDelete(ctx, name)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"success":          true,
		"restart_required": restartRequired,
	}, nil
}

// getOptionalString returns a pointer to the string argument key, or nil
// when the argument is absent, so an update can tell "clear" ("") from
// "keep" (absent).
func getOptionalString(args map[string]interface{}, key string) *string {
	v, ok := args[key].(string)
	if !ok {
		return nil
	}
	return &v
}
