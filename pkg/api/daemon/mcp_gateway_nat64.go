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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// gatewayNAT64Status is the shared MCP NAT64 status path. Both service
// providers route through it so the two cannot report the translator
// differently.
func gatewayNAT64Status(ctx context.Context, backend GatewayNAT64Interface) (interface{}, error) {
	health, err := backend.NAT64Status(ctx)
	if err != nil {
		return nil, err
	}
	out := &rest.NAT64StatusResponse{
		Active:          health.Active,
		InstancePresent: health.InstancePresent,
		Prefix:          health.Prefix,
		Instance:        health.Instance,
		Sessions:        health.Sessions,
		Pool4Used:       health.Pool4Used,
		ModuleVersion:   health.ModuleVersion,
		FlowCount:       health.FlowCount,
		LastReconcile:   health.LastReconcile,
	}
	if health.LastError != nil {
		out.LastError = health.LastError.Error()
	}
	return out, nil
}

// =============================================================================
// MCPServiceProvider — gateway NAT64 operations
// =============================================================================

// SetGatewayNAT64 wires the NAT64 backend into the MCP service provider. A
// nil backend leaves the tool reporting the service unavailable.
func (m *MCPServiceProvider) SetGatewayNAT64(n GatewayNAT64Interface) {
	m.gatewayNAT64 = n
}

// requireGatewayNAT64 resolves the translator backend or reports it absent.
func (m *MCPServiceProvider) requireGatewayNAT64() (GatewayNAT64Interface, error) {
	if m.gatewayNAT64 == nil {
		return nil, ErrServiceNotAvailable{Service: "nat64"}
	}
	return m.gatewayNAT64, nil
}

// GatewayNAT64Status returns the NAT64 translator's health snapshot.
func (m *MCPServiceProvider) GatewayNAT64Status(ctx context.Context) (interface{}, error) {
	backend, err := m.requireGatewayNAT64()
	if err != nil {
		return nil, err
	}
	return gatewayNAT64Status(ctx, backend)
}
