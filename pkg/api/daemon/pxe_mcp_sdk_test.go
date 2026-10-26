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

// connectPXEMCP serves server through the daemon's MCP server, whose pxe_*
// tools require the scope of their gRPC method, and connects the SDK's MCP
// adapter as a caller holding scopes.
func connectPXEMCP(t *testing.T, server platformv1.PXEServiceServer, scopes ...string) grpc.ClientConnInterface {
	t.Helper()
	provider := &MCPServiceProvider{}
	provider.SetPXEServer(server)
	config := mcp.DefaultConfig()
	config.AuthManager = tenantMCPTokens{tokenContexts{phase35MCPToken: &platformtoken.AuthorizedContext{
		Subject: "operator",
		Scopes:  scopes,
	}}}
	// mTLS, because the install-completion webhook authenticates the node by
	// its verified client certificate (#238).
	return serveMCPConfigMTLS(t, provider, config).Connection()
}

// TestSDKMCP_PXEMethods drives every PXEService method through the SDK's MCP
// adapter and the daemon's MCP server.
func TestSDKMCP_PXEMethods(t *testing.T) {
	testSDKPXEMethods(t, "MCP", connectPXEMCP)
}

// TestSDKMCP_PXEMethodsRefuse checks the MCP path refuses a missing scope and
// a missing device with the codes gRPC gives.
func TestSDKMCP_PXEMethodsRefuse(t *testing.T) {
	testSDKPXERefusesScope(t, "MCP", connectPXEMCP)
	testSDKPXERefusesNotFound(t, "MCP", connectPXEMCP)
}
