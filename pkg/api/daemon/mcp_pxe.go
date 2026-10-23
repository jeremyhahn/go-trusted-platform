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

// SetPXEServer wires the PXEService servicer the pxe_* MCP tools call. The
// daemon passes the same servicer it registers on gRPC, so each tool answers
// and refuses exactly as its gRPC method does.
func (p *MCPServiceProvider) SetPXEServer(server platformv1.PXEServiceServer) {
	p.pxeServer = server
}

// PXEServiceServer implements mcp.PXEProvider. It returns nil while no PXE
// service is wired, and the PXE tools then refuse with ErrPXENotConfigured.
func (p *MCPServiceProvider) PXEServiceServer() platformv1.PXEServiceServer {
	return p.pxeServer
}
