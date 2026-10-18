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
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// connectInvitationMCP serves server through the daemon's MCP server, which
// authorizes each platform_invitation_* tool with the scope its gRPC method
// requires, and connects the SDK's MCP adapter as a caller holding scopes.
func connectInvitationMCP(t *testing.T, server platformv1.InvitationServiceServer, scopes ...string) grpc.ClientConnInterface {
	t.Helper()
	provider := &MCPServiceProvider{}
	provider.SetInvitationServer(server)
	config := mcp.DefaultConfig()
	config.AuthManager = tenantMCPTokens{tokenContexts{phase35MCPToken: &platformtoken.AuthorizedContext{
		Subject: "operator",
		Scopes:  scopes,
	}}}
	return serveMCPConfig(t, provider, config).Connection()
}

// TestSDKMCP_InvitationMethods drives every InvitationService method through
// the SDK's MCP adapter and the daemon's platform_invitation_* tools.
func TestSDKMCP_InvitationMethods(t *testing.T) {
	testSDKInvitationMethods(t, "MCP", connectInvitationMCP)
}

// TestSDKMCP_InvitationMethodsRefuse checks the MCP path refuses a missing
// scope and a missing invitation with the codes gRPC gives.
func TestSDKMCP_InvitationMethodsRefuse(t *testing.T) {
	testSDKInvitationRefusesScope(t, "MCP", connectInvitationMCP)
	testSDKInvitationRefusesNotFound(t, "MCP", connectInvitationMCP)
}
