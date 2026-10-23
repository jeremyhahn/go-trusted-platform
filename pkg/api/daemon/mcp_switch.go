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

// SetSwitchServer wires the SwitchService servicer the switch_* MCP tools
// call. The daemon passes the same servicer it registers on gRPC, so each
// tool answers and refuses exactly as its gRPC method does.
func (p *MCPServiceProvider) SetSwitchServer(server platformv1.SwitchServiceServer) {
	p.switchServer = server
}

// SwitchServiceServer implements mcp.SwitchProvider. It returns nil while no
// switch service is wired, and the switch tools then refuse with
// ErrSwitchNotConfigured.
func (p *MCPServiceProvider) SwitchServiceServer() platformv1.SwitchServiceServer {
	return p.switchServer
}
