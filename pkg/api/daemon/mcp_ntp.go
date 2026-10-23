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

package daemon

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// MCP time-synchronization operations
// =============================================================================
//
// Both MCP service providers delegate to the SAME in-process NTPServiceServer
// that backs REST, gRPC, QUIC, and the Unix socket, and return the generated
// platform.v1 response messages verbatim. The MCP transport adapter decodes
// tool results straight into those pb replies, so the tool JSON and the pb
// wire shape stay in lockstep by construction.

// ntpMCPStatus runs the shared MCP status path.
func ntpMCPStatus(ctx context.Context, server platformv1.NTPServiceServer) (interface{}, error) {
	return server.GetStatus(ctx, &platformv1.GetNTPStatusRequest{})
}

// ntpMCPSources runs the shared MCP source-enumeration path.
func ntpMCPSources(ctx context.Context, server platformv1.NTPServiceServer) (interface{}, error) {
	return server.ListSources(ctx, &platformv1.ListNTPSourcesRequest{})
}

// ntpMCPStep runs the shared MCP manual-step path.
func ntpMCPStep(ctx context.Context, server platformv1.NTPServiceServer) (interface{}, error) {
	return server.Step(ctx, &platformv1.StepNTPClockRequest{})
}

// SetNTPService wires the time-synchronization backend into the MCP service
// provider. A nil server leaves every ntp_* tool returning the typed
// service-unavailable error.
func (m *MCPServiceProvider) SetNTPService(server platformv1.NTPServiceServer) {
	m.ntpService = server
}

// requireNTP returns the NTP server or the typed service-unavailable error.
func (m *MCPServiceProvider) requireNTP() (platformv1.NTPServiceServer, error) {
	if m.ntpService == nil {
		return nil, ErrServiceNotAvailable{Service: "ntp"}
	}
	return m.ntpService, nil
}

// NTPStatus returns the node's synchronization state.
func (m *MCPServiceProvider) NTPStatus(ctx context.Context) (interface{}, error) {
	server, err := m.requireNTP()
	if err != nil {
		return nil, err
	}
	return ntpMCPStatus(ctx, server)
}

// NTPSources returns the configured time sources.
func (m *MCPServiceProvider) NTPSources(ctx context.Context) (interface{}, error) {
	server, err := m.requireNTP()
	if err != nil {
		return nil, err
	}
	return ntpMCPSources(ctx, server)
}

// NTPStep forces an immediate clock correction.
func (m *MCPServiceProvider) NTPStep(ctx context.Context) (interface{}, error) {
	server, err := m.requireNTP()
	if err != nil {
		return nil, err
	}
	return ntpMCPStep(ctx, server)
}
