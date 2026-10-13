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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// VPN control-plane Tool Registration
// =============================================================================

// vpnToolSchema builds an object input schema from string properties, the
// first `required` of which are mandatory.
func vpnToolSchema(properties map[string]interface{}, required ...string) map[string]interface{} {
	schema := map[string]interface{}{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func vpnStringProperty(description string) map[string]interface{} {
	return map[string]interface{}{"type": "string", "description": description}
}

// registerVPNTools registers the VPN control-plane MCP tools: peer
// enrolment, session status, and tenant posture policies.
func (r *ToolRegistry) registerVPNTools() {
	tenant := vpnStringProperty("Tenant ID")
	device := vpnStringProperty("Device ID of the peer")
	policyName := vpnStringProperty("Posture policy name ([A-Za-z0-9_.-], at most 64 characters)")
	tenantFilter := vpnStringProperty("Limit the list to one tenant; omit for every tenant")

	r.addTool(mcpwire.ToolDefinition{
		Name: "vpn_peer_enrol",
		Description: "Enrol a device as a VPN peer of a tenant, or replace the zones of an existing enrolment. " +
			"A gateway admits only enrolled peers",
		InputSchema: vpnToolSchema(map[string]interface{}{
			"tenant_id": tenant,
			"device_id": device,
			"zones": map[string]interface{}{
				"type":        "array",
				"items":       map[string]interface{}{"type": "string"},
				"description": "Zones the peer may request, narrowing the gateway's allow-to set; omit for all",
			},
		}, "tenant_id", "device_id"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "vpn_peer_list",
		Description: "List the enrolled VPN peers",
		InputSchema: vpnToolSchema(map[string]interface{}{"tenant_id": tenantFilter}),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "vpn_peer_revoke",
		Description: "Revoke a VPN peer enrolment; the gateways revoke the device's leases when the change reaches them",
		InputSchema: vpnToolSchema(map[string]interface{}{"tenant_id": tenant, "device_id": device}, "tenant_id", "device_id"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name: "vpn_status",
		Description: "Report the VPN session state the gateways last sent in telemetry: running flag, admission and " +
			"refusal counts, active leases, and posture-policy compile errors",
		InputSchema: vpnToolSchema(map[string]interface{}{
			"gateway_id": vpnStringProperty("Limit the status to one gateway; omit for every gateway"),
		}),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "vpn_posture_policy_get",
		Description: "Get a tenant VPN posture policy",
		InputSchema: vpnToolSchema(map[string]interface{}{"tenant_id": tenant, "name": policyName}, "tenant_id", "name"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name: "vpn_posture_policy_set",
		Description: "Create or replace a tenant VPN posture policy. The module must compile as Rego package " +
			"vpn.posture; an invalid module is refused and nothing is stored",
		InputSchema: vpnToolSchema(map[string]interface{}{
			"tenant_id": tenant,
			"name":      policyName,
			"module":    vpnStringProperty("Rego module source (package vpn.posture)"),
		}, "tenant_id", "name", "module"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "vpn_posture_policy_delete",
		Description: "Delete a tenant VPN posture policy",
		InputSchema: vpnToolSchema(map[string]interface{}{"tenant_id": tenant, "name": policyName}, "tenant_id", "name"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "vpn_posture_policy_list",
		Description: "List the VPN posture policies",
		InputSchema: vpnToolSchema(map[string]interface{}{"tenant_id": tenantFilter}),
	})
}

// =============================================================================
// VPN Tool Dispatch
// =============================================================================

type vpnToolExecutor func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error)

// vpnToolExecutors dispatches vpn_* tools (map-based for O(1) routing per
// project conventions). The service validates every argument, so a missing
// one is refused there with the same error every transport returns.
var vpnToolExecutors = map[string]vpnToolExecutor{
	"vpn_peer_enrol": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.VPNEnrolPeer(ctx, getString(args, "tenant_id"), getString(args, "device_id"), getStringSlice(args, "zones"))
	},
	"vpn_peer_list": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.VPNListPeers(ctx, getString(args, "tenant_id"))
	},
	"vpn_peer_revoke": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.VPNRevokePeer(ctx, getString(args, "tenant_id"), getString(args, "device_id"))
	},
	"vpn_status": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.VPNStatus(ctx, getString(args, "gateway_id"))
	},
	"vpn_posture_policy_get": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.VPNPosturePolicyGet(ctx, getString(args, "tenant_id"), getString(args, "name"))
	},
	"vpn_posture_policy_set": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.VPNPosturePolicySet(ctx, getString(args, "tenant_id"), getString(args, "name"), getString(args, "module"))
	},
	"vpn_posture_policy_delete": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.VPNPosturePolicyDelete(ctx, getString(args, "tenant_id"), getString(args, "name"))
	},
	"vpn_posture_policy_list": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.VPNPosturePolicyList(ctx, getString(args, "tenant_id"))
	},
}

// dispatchVPNTool routes vpn_* tools through the executor map. It returns
// handled=false when the tool name is not a VPN tool.
func (r *ToolRegistry) dispatchVPNTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	exec, ok := vpnToolExecutors[name]
	if !ok {
		return nil, false, nil
	}
	result, err := exec(r, ctx, args)
	if err != nil {
		return nil, true, err
	}
	result, err = marshalResult(result)
	return result, true, err
}
