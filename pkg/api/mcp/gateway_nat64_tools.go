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

// registerGatewayNAT64Tools registers the gateway NAT64 MCP tools.
func (r *ToolRegistry) registerGatewayNAT64Tools() {
	r.addTool(mcpwire.ToolDefinition{
		Name: "gateway_nat64_status",
		Description: "Get the NAT64 translator health: whether the kernel instance is present, " +
			"the RFC 6052 translation prefix in use, live session count, pool4 usage and module version",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})
}

// =============================================================================
// Gateway NAT64 Tool Dispatch
// =============================================================================

// gatewayNAT64ToolExecutors dispatches gateway_nat64_* tools (map-based for
// O(1) routing per project conventions).
var gatewayNAT64ToolExecutors = map[string]func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error){
	"gateway_nat64_status": (*ToolRegistry).executeGatewayNAT64Status,
}

// dispatchGatewayNAT64Tool routes gateway_nat64_* tools through the executor
// map. It returns handled=false when the tool name is not a NAT64 tool.
func (r *ToolRegistry) dispatchGatewayNAT64Tool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	exec, ok := gatewayNAT64ToolExecutors[name]
	if !ok {
		return nil, false, nil
	}
	result, err := exec(r, ctx, args)
	return result, true, err
}

// executeGatewayNAT64Status returns the translator's health snapshot.
func (r *ToolRegistry) executeGatewayNAT64Status(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.GatewayNAT64Status(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}
