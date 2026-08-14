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

import "context"

// =============================================================================
// Gateway Perf Error Types
// =============================================================================

// ErrPerfInvalidCount indicates the flow measurement count is out of
// range.
var ErrPerfInvalidCount = &GatewayError{
	Code:    "PERF_INVALID_COUNT",
	Message: "flow count must be 1-100000",
}

// ErrPerfInvalidZone indicates the conntrack zone is out of range.
var ErrPerfInvalidZone = &GatewayError{
	Code:    "PERF_INVALID_ZONE",
	Message: "conntrack zone must be 0-65535",
}

// =============================================================================
// Gateway Perf Tool Registration
// =============================================================================

// perfBridgeProperty is the shared optional bridge schema.
func perfBridgeProperty() map[string]interface{} {
	return map[string]interface{}{
		"type":        "string",
		"description": "Target OVS bridge (default: daemon's default bridge)",
	}
}

// registerGatewayPerfTools registers gateway performance verification MCP
// tools. All results are REAL measurements: flow programming is timed
// against a live bridge and datapath / conntrack values come from
// ovs-vswitchd counters.
func (r *ToolRegistry) registerGatewayPerfTools() {
	r.addTool(ToolDefinition{
		Name:        "gateway_perf_flows",
		Description: "Measure real OpenFlow programming throughput: installs ephemeral flows into a dedicated table, times the install with a monotonic clock, then removes them with a cookie-scoped delete",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"count": map[string]interface{}{
					"type":        "integer",
					"description": "Number of ephemeral flows to install (1-100000, default 1000)",
				},
				"batch": map[string]interface{}{
					"type":        "boolean",
					"description": "Install with a single batched barrier instead of one-by-one",
				},
				"bridge": perfBridgeProperty(),
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_perf_datapath",
		Description: "Read live datapath counters: flow-cache hits/misses/lost, hardware-offloaded flow count, hw-offload configuration state, and bridge datapath type",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge": perfBridgeProperty(),
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "gateway_perf_conntrack",
		Description: "Summarize the connection tracking table: total entries and per-zone counts, optionally restricted to one conntrack zone",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"zone": map[string]interface{}{
					"type":        "integer",
					"description": "Conntrack zone filter (0-65535); omit to summarize every zone",
				},
			},
		},
	})
}

// =============================================================================
// Gateway Perf Tool Dispatch
// =============================================================================

// gatewayPerfToolExecutors dispatches gateway_perf_* tools (map-based for
// O(1) routing per project conventions).
var gatewayPerfToolExecutors = map[string]func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error){
	"gateway_perf_flows":     (*ToolRegistry).executeGatewayPerfFlows,
	"gateway_perf_datapath":  (*ToolRegistry).executeGatewayPerfDatapath,
	"gateway_perf_conntrack": (*ToolRegistry).executeGatewayPerfConntrack,
}

// dispatchGatewayPerfTool routes gateway_perf_* tools through the
// executor map. It returns handled=false when the tool name is not a
// perf tool.
func (r *ToolRegistry) dispatchGatewayPerfTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	exec, ok := gatewayPerfToolExecutors[name]
	if !ok {
		return nil, false, nil
	}
	result, err := exec(r, ctx, args)
	return result, true, err
}

func (r *ToolRegistry) executeGatewayPerfFlows(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	count := getInt(args, "count")
	if count < 0 || count > 100000 {
		return nil, ErrPerfInvalidCount
	}
	result, err := r.service.GatewayPerfFlows(ctx, getString(args, "bridge"), count, getBool(args, "batch"))
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayPerfDatapath(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.GatewayPerfDatapath(ctx, getString(args, "bridge"))
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayPerfConntrack(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	zone := -1
	if _, present := args["zone"]; present {
		zone = getInt(args, "zone")
		if zone < 0 || zone > 65535 {
			return nil, ErrPerfInvalidZone
		}
	}
	result, err := r.service.GatewayPerfConntrack(ctx, zone)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}
