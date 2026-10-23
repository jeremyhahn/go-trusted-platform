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

// SetBMCServer wires the BMCService servicer the platform_bmc_* MCP tools
// call. The daemon passes the same servicer it registers on gRPC, so each
// tool answers and refuses exactly as its gRPC method does.
func (p *MCPServiceProvider) SetBMCServer(server platformv1.BMCServiceServer) {
	p.bmcServer = server
}

// BMCServiceServer implements mcp.BMCProvider. It returns nil while no BMC
// service is wired, and the BMC tools then refuse with ErrBMCNotConfigured.
func (p *MCPServiceProvider) BMCServiceServer() platformv1.BMCServiceServer {
	return p.bmcServer
}
