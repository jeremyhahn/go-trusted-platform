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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SetTenantService wires the TenantService into the MCP service provider, so
// the tenant_* and platform_tenant_barrier_* tools call the same server that
// backs REST, gRPC, QUIC and the Unix socket. A nil server leaves every
// tenant tool answering the typed service-unavailable error.
func (m *MCPServiceProvider) SetTenantService(server platformv1.TenantServiceServer) {
	m.tenantService = server
}

// TenantService returns the TenantService the tenant tools call, or nil when
// none is wired (mcp.TenantServiceProvider).
func (m *MCPServiceProvider) TenantService() platformv1.TenantServiceServer {
	return m.tenantService
}
