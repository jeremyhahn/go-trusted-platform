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

package quicwire

// Wire shapes of the gateway status and mode sub-opcodes (OpGatewayStatus,
// OpGatewaySetMode). The server handler and the SDK adapter share them so
// the two ends cannot drift.

// Gateway mode bits, matching the gRPC GatewayModeEnum values.
const (
	GatewayModeOverlay uint32 = 1
	GatewayModeEdge    uint32 = 2
	GatewayModeTransit uint32 = 4

	// GatewayModesAll is every defined mode bit; a mask with any other bit
	// set is invalid.
	GatewayModesAll = GatewayModeOverlay | GatewayModeEdge | GatewayModeTransit
)

// GatewayStatusInfo is the gateway status: the gRPC GatewayStatus with its
// start time as Unix seconds.
type GatewayStatusInfo struct {
	ID     string `codec:"id"`
	NodeID string `codec:"node_id"`
	// Modes is the GatewayModeEnum bitmask (overlay 1, edge 2, transit 4).
	Modes         uint32  `codec:"modes"`
	Tier          string  `codec:"tier,omitempty"`
	Reputation    float64 `codec:"reputation"`
	UptimeSeconds uint64  `codec:"uptime_seconds"`
	Healthy       bool    `codec:"healthy"`
	// StartedAt is Unix seconds; zero means unknown.
	StartedAt int64 `codec:"started_at,omitempty"`
}

// GatewayStatusRequest represents a status request.
type GatewayStatusRequest struct{}

// GatewayStatusResponse represents a status response.
type GatewayStatusResponse struct {
	Status    *GatewayStatusInfo `codec:"status"`
	Timestamp int64              `codec:"timestamp"`
}

// GatewaySetModeRequest sets the gateway's active modes.
type GatewaySetModeRequest struct {
	// Modes is the GatewayModeEnum bitmask; zero is refused.
	Modes uint32 `codec:"modes"`
}

// GatewaySetModeResponse carries the gateway status after the change.
type GatewaySetModeResponse struct {
	Status    *GatewayStatusInfo `codec:"status"`
	Success   bool               `codec:"success"`
	Timestamp int64              `codec:"timestamp"`
}
