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

// SetInvitationServer wires the InvitationService servicer the
// platform_invitation_* MCP tools call. The daemon passes the same servicer
// it registers on gRPC, so each tool answers and refuses exactly as its gRPC
// method does.
func (p *MCPServiceProvider) SetInvitationServer(server platformv1.InvitationServiceServer) {
	p.invitationServer = server
}

// InvitationServiceServer returns the InvitationService servicer, or nil
// while none is wired.
func (p *MCPServiceProvider) InvitationServiceServer() platformv1.InvitationServiceServer {
	return p.invitationServer
}
