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
// NTP (time synchronization) Tool Registration
// =============================================================================

// emptyObjectSchema is the input schema for the NTP tools, none of which take
// parameters.
func emptyObjectSchema() map[string]interface{} {
	return map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}
}

// registerNTPTools registers the time-synchronization MCP tools. Results come
// straight from chronyd's control socket — they are live measurements, never
// cached guesses.
func (r *ToolRegistry) registerNTPTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name: "ntp_status",
		Description: "Report the node's clock synchronization state: synced flag, stratum, leap status, " +
			"current offset, root dispersion, last sync time, serve/consume mode, reachable source count, " +
			"and whether a large post-convergence correction was flagged as an anomaly",
		InputSchema: emptyObjectSchema(),
	})

	r.addTool(mcpwire.ToolDefinition{
		Name: "ntp_sources",
		Description: "List every configured time source with its selection state, stratum, poll interval, " +
			"reachability register, last receive time, and measured offset",
		InputSchema: emptyObjectSchema(),
	})

	r.addTool(mcpwire.ToolDefinition{
		Name: "ntp_step",
		Description: "Force an immediate clock correction (operator recovery). Fails when no time source is " +
			"reachable rather than moving the clock on stale data",
		InputSchema: emptyObjectSchema(),
	})
}

// =============================================================================
// NTP Tool Dispatch
// =============================================================================

// ntpToolExecutors dispatches ntp_* tools (map-based for O(1) routing per
// project conventions).
var ntpToolExecutors = map[string]func(*ToolRegistry, context.Context) (interface{}, error){
	"ntp_status":  (*ToolRegistry).executeNTPStatus,
	"ntp_sources": (*ToolRegistry).executeNTPSources,
	"ntp_step":    (*ToolRegistry).executeNTPStep,
}

// dispatchNTPTool routes ntp_* tools through the executor map. It returns
// handled=false when the tool name is not an NTP tool.
func (r *ToolRegistry) dispatchNTPTool(ctx context.Context, name string) (interface{}, bool, error) {
	exec, ok := ntpToolExecutors[name]
	if !ok {
		return nil, false, nil
	}
	result, err := exec(r, ctx)
	return result, true, err
}

// executeNTPStatus returns the node's synchronization state.
func (r *ToolRegistry) executeNTPStatus(ctx context.Context) (interface{}, error) {
	result, err := r.service.NTPStatus(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeNTPSources returns the configured time sources.
func (r *ToolRegistry) executeNTPSources(ctx context.Context) (interface{}, error) {
	result, err := r.service.NTPSources(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeNTPStep forces an immediate clock correction.
func (r *ToolRegistry) executeNTPStep(ctx context.Context) (interface{}, error) {
	result, err := r.service.NTPStep(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}
