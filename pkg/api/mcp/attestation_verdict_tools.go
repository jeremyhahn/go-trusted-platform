// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"math"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// DeviceVerdictProvider is the optional MCP provider for the device verdict
// feed (#709). MCP carries no streams, so a client follows the feed by
// long-polling attestation_device_verdicts_poll from a cursor.
type DeviceVerdictProvider interface {
	// AttestationPollDeviceVerdicts returns the verdicts after cursor the
	// caller of ctx may see, waiting up to waitMs for the first one. An
	// empty cursor answers the feed's head at once.
	AttestationPollDeviceVerdicts(ctx context.Context, cursor string, waitMs uint32) (any, error)
}

// ErrDeviceVerdictsNotConfigured reports a node with no device verdict feed
// behind the MCP tool.
var ErrDeviceVerdictsNotConfigured = &AttestationError{
	Code:    "DEVICE_VERDICTS_NOT_CONFIGURED",
	Message: "the device verdict feed is not configured on this node",
}

func (r *ToolRegistry) deviceVerdictProvider() DeviceVerdictProvider {
	if p, ok := r.service.(DeviceVerdictProvider); ok {
		return p
	}
	return nil
}

func (r *ToolRegistry) registerAttestationVerdictTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name: "attestation_device_verdicts_poll",
		Description: "Long-poll the device attestation verdicts recorded after a cursor. " +
			"Call with no cursor for the feed's head, then pass each reply's cursor to the next call.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"cursor":  map[string]interface{}{"type": "string", "description": "Cursor from the previous reply; empty for the feed's head"},
				"wait_ms": map[string]interface{}{"type": "integer", "description": "How long to wait for a verdict, in milliseconds; the daemon waits at most 20000"},
			},
		},
	})
}

func (r *ToolRegistry) executeAttestationVerdictsPoll(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceVerdictProvider()
	if p == nil {
		return nil, ErrDeviceVerdictsNotConfigured
	}
	page, err := p.AttestationPollDeviceVerdicts(ctx, getString(args, "cursor"), waitMillis(args))
	if err != nil {
		return nil, err
	}
	return marshalResult(page)
}

// waitMillis reads wait_ms, clamped to the uint32 the poll carries.
func waitMillis(args map[string]interface{}) uint32 {
	return uint32(min(max(getInt64(args, "wait_ms"), 0), math.MaxUint32))
}
